/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"strconv"
	"time"

	"github.com/openstack-k8s-operators/lib-common/modules/common"
	"github.com/openstack-k8s-operators/lib-common/modules/common/condition"
	"github.com/openstack-k8s-operators/lib-common/modules/common/configmap"
	"github.com/openstack-k8s-operators/lib-common/modules/common/env"
	"github.com/openstack-k8s-operators/lib-common/modules/common/helper"
	"github.com/openstack-k8s-operators/lib-common/modules/common/job"
	common_rbac "github.com/openstack-k8s-operators/lib-common/modules/common/rbac"
	"github.com/openstack-k8s-operators/lib-common/modules/common/util"
	testv1beta1 "github.com/openstack-k8s-operators/test-operator/api/v1beta1"
	"github.com/openstack-k8s-operators/test-operator/pkg/horizon"
	"gopkg.in/yaml.v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	k8s_errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// HorizonReconciler reconciles a Horizon object
type HorizonReconciler struct {
	Reconciler
}

//+kubebuilder:rbac:groups=test.openstack.org,resources=horizons,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=test.openstack.org,resources=horizons/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=test.openstack.org,resources=horizons/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=pods,verbs=create;delete;get;list;patch;update;watch
//+kubebuilder:rbac:groups="",resources=persistentvolumeclaims,verbs=get;list;create;update;watch;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Horizon object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.14.1/pkg/reconcile
func (r *HorizonReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {

	// How much time should we wait before calling Reconcile loop when there is a failure
	requeueAfter := time.Second * 60

	logging := log.FromContext(ctx)
	instance := &testv1beta1.Horizon{}
	err := r.Client.Get(ctx, req.NamespacedName, instance)
	if err != nil {
		if k8s_errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Check whether the user wants to execute workflow
	workflowActive := false
	if len(instance.Spec.Workflow) > 0 {
		workflowActive = true
	}

	helper, err := helper.NewHelper(
		instance,
		r.Client,
		r.Kclient,
		r.Scheme,
		r.Log,
	)

	rbacRules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{"security.openshift.io"},
			ResourceNames: []string{"anyuid", "privileged"},
			Resources:     []string{"securitycontextconstraints"},
			Verbs:         []string{"use"},
		},
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"create", "get", "list", "watch", "update", "patch", "delete"},
		},
	}

	rbacResult, err := common_rbac.ReconcileRbac(ctx, helper, instance, rbacRules)
	if err != nil {
		return rbacResult, err
	} else if (rbacResult != ctrl.Result{}) {
		return rbacResult, nil
	}

	instance.Status.Conditions.MarkTrue(condition.InputReadyCondition, condition.InputReadyMessage)

	serviceLabels := map[string]string{
		common.AppSelector: horizon.ServiceName,
		"instanceName":     instance.Name,
		"operator":         "test-operator",
	}

	result, err := r.EnsureHorizonCloudsYAML(ctx, instance, helper, serviceLabels)

	if err != nil {
		return result, err
	}

	// Create PersistentVolumeClaim
	ctrlResult, err := r.EnsureLogsPVCExists(
		ctx,
		instance,
		helper,
		serviceLabels,
		instance.Spec.StorageClass,
	)
	if err != nil {
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		return ctrlResult, nil
	}
	// Create PersistentVolumeClaim - end

	// Create Job
	mountCerts := r.CheckSecretExists(ctx, instance, "combined-ca-bundle")

	mountKeys := false
	if (len(instance.Spec.PublicKey) == 0) || (len(instance.Spec.PrivateKey) == 0) {
		logging.Info("Both values privateKey and publicKey need to be specified. Keys not mounted.")
	} else {
		mountKeys = true
	}

	mountKubeconfig := false
	if len(instance.Spec.KubeconfigSecretName) != 0 {
		mountKubeconfig = true
	}

	// If the current job is executing the last workflow step -> do not create another job
	if r.JobExists(ctx, instance) {
		return ctrl.Result{}, nil
	}

	// We are about to start job that spawns the pod with tests.
	// This lock ensures that there is always only one pod running.
	if !r.AcquireLock(ctx, instance, helper, instance.Spec.Parallel) {
		logging.Info("Cannot acquire lock")
		return ctrl.Result{RequeueAfter: requeueAfter}, nil
	}
	logging.Info("Lock acquired")

	// Prepare Horizon env vars
	envVars := r.PrepareHorizonEnvVars(ctx, serviceLabels, instance, helper)
	jobName := r.GetJobName(instance, 0)
	logsPVCName := r.GetPVCLogsName(instance)
	jobDef := horizon.Job(
		instance,
		serviceLabels,
		jobName,
		logsPVCName,
		mountCerts,
		mountKeys,
		mountKubeconfig,
		envVars,
	)
	horizonJob := job.NewJob(
		jobDef,
		testv1beta1.ConfigHash,
		true,
		time.Duration(5)*time.Second,
		"",
	)

	ctrlResult, err = horizonJob.DoJob(ctx, helper)
	if err != nil {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.DeploymentReadyCondition,
			condition.ErrorReason,
			condition.SeverityWarning,
			condition.DeploymentReadyErrorMessage,
			err.Error()))
		return ctrlResult, err
	} else if (ctrlResult != ctrl.Result{}) {
		instance.Status.Conditions.Set(condition.FalseCondition(
			condition.DeploymentReadyCondition,
			condition.RequestedReason,
			condition.SeverityInfo,
			condition.DeploymentReadyRunningMessage))
		return ctrlResult, nil
	}
	// create Job - end

	r.Log.Info("Reconciled Service successfully")
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *HorizonReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&testv1beta1.Horizon{}).
		Owns(&batchv1.Job{}).
		Owns(&corev1.Secret{}).
		Owns(&corev1.ConfigMap{}).
		Complete(r)
}

// Horizon requires password value to be present in clouds.yaml
// This code ensures that we set a default value of 12345678 when
// password value is missing in the clouds.yaml
func (r *HorizonReconciler) EnsureHorizonCloudsYAML(ctx context.Context, instance client.Object, helper *helper.Helper, labels map[string]string) (ctrl.Result, error) {
	cm, _, _ := configmap.GetConfigMap(ctx, helper, instance, "openstack-config", time.Second*10)
	result := make(map[interface{}]interface{})

	err := yaml.Unmarshal([]byte(cm.Data["clouds.yaml"]), &result)
	if err != nil {
		return ctrl.Result{}, err
	}

	clouds := result["clouds"].(map[interface{}]interface{})
	default_value := clouds["default"].(map[interface{}]interface{})
	auth := default_value["auth"].(map[interface{}]interface{})

	if _, ok := auth["password"].(string); !ok {
		auth["password"] = "12345678"
	}

	yamlString, err := yaml.Marshal(result)
	if err != nil {
		return ctrl.Result{}, err
	}

	cms := []util.Template{
		{
			Name:      "horizon-clouds-config",
			Namespace: instance.GetNamespace(),
			Labels:    labels,
			CustomData: map[string]string{
				"clouds.yaml": string(yamlString),
			},
		},
	}
	configmap.EnsureConfigMaps(ctx, helper, instance, cms, nil)

	return ctrl.Result{}, nil
}

func (r *HorizonReconciler) PrepareHorizonEnvVars(
    ctx context.Context,
    labels map[string]string,
    instance *testv1beta1.Horizon,
    helper *helper.Helper,
) map[string]env.Setter {
    // Prepare env vars
    envVars := make(map[string]env.Setter)
    envVars["USE_EXTERNAL_FILES"] = env.SetValue("True")
    envVars["HORIZON_LOGS_DIR_NAME"] = env.SetValue("horizon")

    // Mandatory variables
    adminUsername := r.GetValue(ctx, instance.Spec, "AdminUsername", "string").(string)
    adminPassword := r.GetValue(ctx, instance.Spec, "AdminPassword", "string").(string)
    dashboardUrl := r.GetValue(ctx, instance.Spec, "DashboardUrl", "string").(string)
    authUrl := r.GetValue(ctx, instance.Spec, "AuthUrl", "string").(string)
    repoUrl := r.GetValue(ctx, instance.Spec, "RepoUrl", "string").(string)
    horizonRepoBranch := r.GetValue(ctx, instance.Spec, "HorizonRepoBranch", "string").(string)

    envVars["ADMIN_USERNAME"] = env.SetValue(adminUsername)
    envVars["ADMIN_PASSWORD"] = env.SetValue(adminPassword)
    envVars["DASHBOARD_URL"] = env.SetValue(dashboardUrl)
    envVars["AUTH_URL"] = env.SetValue(authUrl)
    envVars["REPO_URL"] = env.SetValue(repoUrl)
    envVars["HORIZON_REPO_BRANCH"] = env.SetValue(horizonRepoBranch)

    // Horizon specific configuration
    envVars["IMAGE_FILE"] = env.SetValue("/var/lib/horizontest/cirros-0.6.2-x86_64-disk.img")
    envVars["IMAGE_FILE_NAME"] = env.SetValue("cirros-0.6.2-x86_64-disk")
    envVars["IMAGE_URL"] = env.SetValue("http://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img")
    envVars["PROJECT_NAME"] = env.SetValue("horizontest")
    envVars["USER_NAME"] = env.SetValue("horizontest")
    envVars["PASSWORD"] = env.SetValue("horizontest")
    envVars["FLAVOR_NAME"] = env.SetValue("m1.tiny")

    envVars["HORIZON_KEYS_FOLDER"] = env.SetValue("/etc/test_operator")

    // Prepare custom data
    customData := make(map[string]string)
    horizonConf := r.GetValue(ctx, instance.Spec, "Config", "string").(string)
    customData["horizon.conf"] = horizonConf

    privateKeyData := make(map[string]string)
    privateKey := r.GetValue(ctx, instance.Spec, "PrivateKey", "string").(string)
    privateKeyData["id_ecdsa"] = privateKey

    publicKeyData := make(map[string]string)
    publicKey := r.GetValue(ctx, instance.Spec, "PublicKey", "string").(string)
    publicKeyData["id_ecdsa.pub"] = publicKey

    cms := []util.Template{
        {
            Name:         instance.Name + "horizon-config",
            Namespace:    instance.Namespace,
            InstanceType: instance.Kind,
            Labels:       labels,
            CustomData:   customData,
        },
        {
            Name:         instance.Name + "horizon-private-key",
            Namespace:    instance.Namespace,
            InstanceType: instance.Kind,
            Labels:       labels,
            CustomData:   privateKeyData,
        },
        {
            Name:         instance.Name + "horizon-public-key",
            Namespace:    instance.Namespace,
            InstanceType: instance.Kind,
            Labels:       labels,
            CustomData:   publicKeyData,
        },
    }

    configmap.EnsureConfigMaps(ctx, helper, instance, cms, nil)

    return envVars
}
