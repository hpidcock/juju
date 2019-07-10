// Copyright 2019 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package provider_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/golang/mock/gomock"
	jujuclock "github.com/juju/clock"
	jc "github.com/juju/testing/checkers"
	gc "gopkg.in/check.v1"
	"gopkg.in/juju/worker.v1/workertest"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	k8sstorage "k8s.io/api/storage/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	watch "k8s.io/apimachinery/pkg/watch"

	"github.com/juju/juju/api"
	"github.com/juju/juju/apiserver/params"
	"github.com/juju/juju/caas/kubernetes/provider"
	"github.com/juju/juju/cloudconfig/podcfg"
	"github.com/juju/juju/controller"
	k8sannotations "github.com/juju/juju/core/annotations"
	"github.com/juju/juju/environs/config"
	envtesting "github.com/juju/juju/environs/testing"
	"github.com/juju/juju/mongo"
	"github.com/juju/juju/testing"
	coretesting "github.com/juju/juju/testing"
	jujuversion "github.com/juju/juju/version"
)

type bootstrapSuite struct {
	BaseSuite

	controllerCfg controller.Config
	pcfg          *podcfg.ControllerPodConfig

	controllerStackerGetter func() provider.ControllerStackerForTest
}

var _ = gc.Suite(&bootstrapSuite{})

func (s *bootstrapSuite) SetUpTest(c *gc.C) {

	controllerName := "controller-1"

	s.BaseSuite.SetUpTest(c)

	cfg, err := config.New(config.UseDefaults, testing.FakeConfig().Merge(testing.Attrs{
		config.NameKey:              "controller",
		provider.OperatorStorageKey: "",
		provider.WorkloadStorageKey: "",
	}))
	c.Assert(err, jc.ErrorIsNil)
	s.cfg = cfg

	s.controllerUUID = "9bec388c-d264-4cde-8b29-3e675959157a"

	s.controllerCfg = testing.FakeControllerConfig()
	pcfg, err := podcfg.NewBootstrapControllerPodConfig(s.controllerCfg, controllerName, "bionic")
	c.Assert(err, jc.ErrorIsNil)

	pcfg.JujuVersion = jujuversion.Current
	pcfg.APIInfo = &api.Info{
		Password: "password",
		CACert:   coretesting.CACert,
		ModelTag: coretesting.ModelTag,
	}
	pcfg.Controller.MongoInfo = &mongo.MongoInfo{
		Password: "password", Info: mongo.Info{CACert: coretesting.CACert},
	}
	pcfg.Bootstrap.ControllerModelConfig = s.cfg
	pcfg.Bootstrap.BootstrapMachineInstanceId = "instance-id"
	pcfg.Bootstrap.HostedModelConfig = map[string]interface{}{
		"name": "hosted-model",
	}
	pcfg.Bootstrap.StateServingInfo = params.StateServingInfo{
		Cert:         coretesting.ServerCert,
		PrivateKey:   coretesting.ServerKey,
		CAPrivateKey: coretesting.CAKey,
		StatePort:    123,
		APIPort:      456,
	}
	pcfg.Bootstrap.StateServingInfo = params.StateServingInfo{
		Cert:         coretesting.ServerCert,
		PrivateKey:   coretesting.ServerKey,
		CAPrivateKey: coretesting.CAKey,
		StatePort:    123,
		APIPort:      456,
	}
	pcfg.Bootstrap.ControllerConfig = s.controllerCfg
	s.pcfg = pcfg
	s.controllerStackerGetter = func() provider.ControllerStackerForTest {
		controllerStacker, err := provider.NewcontrollerStackForTest(
			envtesting.BootstrapContext(c), "juju-controller-test", "some-storage", s.broker, s.pcfg,
		)
		c.Assert(err, jc.ErrorIsNil)
		return controllerStacker
	}
}

func (s *bootstrapSuite) TestControllerCorelation(c *gc.C) {
	ctrl := s.setupController(c)
	defer ctrl.Finish()

	existingNs := core.Namespace{}
	existingNs.SetName("controller-1")
	existingNs.SetAnnotations(map[string]string{
		"juju.io/model":         s.cfg.UUID(),
		"juju.io/controller":    s.controllerUUID,
		"juju.io/is-controller": "true",
	})

	c.Assert(s.broker.GetCurrentNamespace(), jc.DeepEquals, "controller")
	c.Assert(s.broker.GetAnnotations().ToMap(), jc.DeepEquals, map[string]string{
		"juju.io/model":      s.cfg.UUID(),
		"juju.io/controller": s.controllerUUID,
	})

	gomock.InOrder(
		s.mockNamespaces.EXPECT().List(v1.ListOptions{IncludeUninitialized: true}).Times(1).
			Return(&core.NamespaceList{Items: []core.Namespace{existingNs}}, nil),
	)
	var err error
	s.broker, err = provider.ControllerCorelation(s.broker)
	c.Assert(err, jc.ErrorIsNil)

	c.Assert(
		// "is-controller" is set as well.
		s.broker.GetAnnotations().ToMap(), jc.DeepEquals,
		map[string]string{
			"juju.io/model":         s.cfg.UUID(),
			"juju.io/controller":    s.controllerUUID,
			"juju.io/is-controller": "true",
		},
	)
	// controller namespace linked back(changed from 'controller' to 'controller-1')
	c.Assert(s.broker.GetCurrentNamespace(), jc.DeepEquals, "controller-1")
}

func (s *bootstrapSuite) TestGetControllerSvcSpec(c *gc.C) {
	ctrl := s.setupController(c)
	defer ctrl.Finish()

	for cloudType, out := range map[string]*provider.ControllerServiceSpec{
		"azure": {
			ServiceType: core.ServiceTypeLoadBalancer,
		},
		"ec2": {
			ServiceType: core.ServiceTypeLoadBalancer,
			Annotations: k8sannotations.New(nil).
				Add("service.beta.kubernetes.io/aws-load-balancer-backend-protocol", "tcp"),
		},
		"gce": {
			ServiceType: core.ServiceTypeLoadBalancer,
		},
		"microk8s": {
			ServiceType: core.ServiceTypeClusterIP,
		},
		"openstack": {
			ServiceType: core.ServiceTypeLoadBalancer,
		},
		"maas": {
			ServiceType: core.ServiceTypeLoadBalancer,
		},
		"lxd": {
			ServiceType: core.ServiceTypeClusterIP,
		},
		"unknown-cloud": {
			ServiceType: core.ServiceTypeLoadBalancer,
		},
	} {
		spec, _ := s.controllerStackerGetter().GetControllerSvcSpec(cloudType)
		c.Check(spec, jc.DeepEquals, out)
	}
}

func (s *bootstrapSuite) TestBootstrap(c *gc.C) {
	ctrl := gomock.NewController(c)
	defer ctrl.Finish()
	// Eventually the namespace wil be set to controllerName.
	// So we have to specify the final namespace(controllerName) for later use.
	newK8sRestClientFunc := s.setupK8sRestClient(c, ctrl, s.pcfg.ControllerName)
	newK8sWatcherForTest := func(wi watch.Interface, name string, clock jujuclock.Clock) (*provider.KubernetesWatcher, error) {
		w, err := provider.NewKubernetesWatcher(wi, name, clock)
		c.Assert(err, jc.ErrorIsNil)
		<-w.Changes() // Consume initial event for testing.
		s.watchers = append(s.watchers, w)
		return w, err
	}
	s.setupBroker(c, ctrl, newK8sRestClientFunc, newK8sWatcherForTest)
	// Broker's namespace is "controller" now - controllerModelConfig.Name()
	c.Assert(s.broker.GetCurrentNamespace(), jc.DeepEquals, "controller")
	c.Assert(
		s.broker.GetAnnotations().ToMap(), jc.DeepEquals,
		map[string]string{
			"juju.io/model":      s.cfg.UUID(),
			"juju.io/controller": s.controllerUUID,
		},
	)

	// These two are done in broker.Bootstrap method actually.
	s.broker.SetNamespace("controller-1")
	s.broker.GetAnnotations().Add("juju.io/is-controller", "true")

	s.pcfg.Bootstrap.Timeout = 10 * time.Minute

	controllerStacker := s.controllerStackerGetter()
	// Broker's namespace should be set to controller name now.
	c.Assert(s.broker.GetCurrentNamespace(), jc.DeepEquals, "controller-1")
	c.Assert(
		// "is-controller" is set as well.
		s.broker.GetAnnotations().ToMap(), jc.DeepEquals,
		map[string]string{
			"juju.io/model":         s.cfg.UUID(),
			"juju.io/controller":    s.controllerUUID,
			"juju.io/is-controller": "true",
		},
	)

	sharedSecret, sslKey := controllerStacker.GetSharedSecretAndSSLKey(c)

	scName := "some-storage"
	sc := k8sstorage.StorageClass{
		ObjectMeta: v1.ObjectMeta{
			Name: scName,
		},
	}

	APIPort := s.controllerCfg.APIPort()
	ns := &core.Namespace{ObjectMeta: v1.ObjectMeta{Name: s.getNamespace()}}
	ns.Name = s.getNamespace()
	s.ensureJujuNamespaceAnnotations(true, ns)
	svcNotProvisioned := &core.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-service",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Spec: core.ServiceSpec{
			Selector: map[string]string{"juju-app": "juju-controller-test"},
			Type:     core.ServiceType("LoadBalancer"),
			Ports: []core.ServicePort{
				{
					Name:       "api-server",
					TargetPort: intstr.FromInt(APIPort),
					Port:       int32(APIPort),
				},
			},
		},
	}

	svcPublicIP := "1.1.1.1"
	svcProvisioned := &core.Service{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-service",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Spec: core.ServiceSpec{
			Selector: map[string]string{"juju-app": "juju-controller-test"},
			Type:     core.ServiceType("LoadBalancer"),
			Ports: []core.ServicePort{
				{
					Name:       "api-server",
					TargetPort: intstr.FromInt(APIPort),
					Port:       int32(APIPort),
				},
			},
			LoadBalancerIP: svcPublicIP,
		},
	}

	emptySecret := &core.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-secret",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Type: core.SecretTypeOpaque,
	}
	secretWithSharedSecretAdded := &core.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-secret",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Type: core.SecretTypeOpaque,
		Data: map[string][]byte{
			"shared-secret": []byte(sharedSecret),
		},
	}
	secretWithServerPEMAdded := &core.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-secret",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Type: core.SecretTypeOpaque,
		Data: map[string][]byte{
			"shared-secret": []byte(sharedSecret),
			"server.pem":    []byte(sslKey),
		},
	}

	emptyConfigMap := &core.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-configmap",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
	}
	bootstrapParamsContent, err := s.pcfg.Bootstrap.StateInitializationParams.Marshal()
	c.Assert(err, jc.ErrorIsNil)

	configMapWithBootstrapParamsAdded := &core.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-configmap",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Data: map[string]string{
			"bootstrap-params": string(bootstrapParamsContent),
		},
	}
	configMapWithAgentConfAdded := &core.ConfigMap{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test-configmap",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Data: map[string]string{
			"bootstrap-params": string(bootstrapParamsContent),
			"agent.conf":       controllerStacker.GetAgentConfigContent(c),
		},
	}

	numberOfPods := int32(1)
	fileMode := int32(256)
	statefulSetSpec := &apps.StatefulSet{
		ObjectMeta: v1.ObjectMeta{
			Name:      "juju-controller-test",
			Labels:    map[string]string{"juju-app": "juju-controller-test"},
			Namespace: s.getNamespace(),
		},
		Spec: apps.StatefulSetSpec{
			ServiceName: "juju-controller-test-service",
			Replicas:    &numberOfPods,
			Selector: &v1.LabelSelector{
				MatchLabels: map[string]string{"juju-app": "juju-controller-test"},
			},
			VolumeClaimTemplates: []core.PersistentVolumeClaim{
				{
					ObjectMeta: v1.ObjectMeta{
						Name:   "storage",
						Labels: map[string]string{"juju-app": "juju-controller-test"},
					},
					Spec: core.PersistentVolumeClaimSpec{
						StorageClassName: &scName,
						AccessModes:      []core.PersistentVolumeAccessMode{core.ReadWriteOnce},
						Resources: core.ResourceRequirements{
							Requests: core.ResourceList{
								core.ResourceStorage: controllerStacker.GetStorageSize(),
							},
						},
					},
				},
			},
			Template: core.PodTemplateSpec{
				ObjectMeta: v1.ObjectMeta{
					Name:      "controller-0",
					Labels:    map[string]string{"juju-app": "juju-controller-test"},
					Namespace: s.getNamespace(),
				},
				Spec: core.PodSpec{
					RestartPolicy: core.RestartPolicyAlways,
					Volumes: []core.Volume{
						{
							Name: "juju-controller-test-server-pem",
							VolumeSource: core.VolumeSource{
								Secret: &core.SecretVolumeSource{
									SecretName:  "juju-controller-test-secret",
									DefaultMode: &fileMode,
									Items: []core.KeyToPath{
										{
											Key:  "server.pem",
											Path: "template-server.pem",
										},
									},
								},
							},
						},
						{
							Name: "juju-controller-test-shared-secret",
							VolumeSource: core.VolumeSource{
								Secret: &core.SecretVolumeSource{
									SecretName:  "juju-controller-test-secret",
									DefaultMode: &fileMode,
									Items: []core.KeyToPath{
										{
											Key:  "shared-secret",
											Path: "shared-secret",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	volAgentConf := core.Volume{
		Name: "juju-controller-test-agent-conf",
		VolumeSource: core.VolumeSource{
			ConfigMap: &core.ConfigMapVolumeSource{
				Items: []core.KeyToPath{
					{
						Key:  "agent.conf",
						Path: "template-agent.conf",
					},
				},
			},
		},
	}
	volAgentConf.VolumeSource.ConfigMap.Name = "juju-controller-test-configmap"
	volBootstrapParams := core.Volume{
		Name: "juju-controller-test-bootstrap-params",
		VolumeSource: core.VolumeSource{
			ConfigMap: &core.ConfigMapVolumeSource{
				Items: []core.KeyToPath{
					{
						Key:  "bootstrap-params",
						Path: "bootstrap-params",
					},
				},
			},
		},
	}
	volBootstrapParams.VolumeSource.ConfigMap.Name = "juju-controller-test-configmap"
	statefulSetSpec.Spec.Template.Spec.Volumes = append(statefulSetSpec.Spec.Template.Spec.Volumes,
		[]core.Volume{
			volAgentConf, volBootstrapParams,
		}...,
	)

	probCmds := &core.ExecAction{
		Command: []string{
			"mongo",
			fmt.Sprintf("--port=%d", s.controllerCfg.StatePort()),
			"--ssl",
			"--sslAllowInvalidHostnames",
			"--sslAllowInvalidCertificates",
			"--sslPEMKeyFile=/var/lib/juju/server.pem",
			"--eval",
			"db.adminCommand('ping')",
		},
	}
	statefulSetSpec.Spec.Template.Spec.Containers = []core.Container{
		{
			Name:            "mongodb",
			ImagePullPolicy: core.PullIfNotPresent,
			Image:           "jujusolutions/juju-db:4.0",
			Command: []string{
				"mongod",
			},
			Args: []string{
				"--dbpath=/var/lib/juju/db",
				"--sslPEMKeyFile=/var/lib/juju/server.pem",
				"--sslPEMKeyPassword=ignored",
				"--sslMode=requireSSL",
				fmt.Sprintf("--port=%d", s.controllerCfg.StatePort()),
				"--journal",
				"--replSet=juju",
				"--quiet",
				"--oplogSize=1024",
				"--ipv6",
				"--auth",
				"--keyFile=/var/lib/juju/shared-secret",
				"--storageEngine=wiredTiger",
				"--bind_ip_all",
			},
			Ports: []core.ContainerPort{
				{
					Name:          "mongodb",
					ContainerPort: int32(s.controllerCfg.StatePort()),
					Protocol:      "TCP",
				},
			},
			ReadinessProbe: &core.Probe{
				Handler: core.Handler{
					Exec: probCmds,
				},
				FailureThreshold:    3,
				InitialDelaySeconds: 5,
				PeriodSeconds:       10,
				SuccessThreshold:    1,
				TimeoutSeconds:      1,
			},
			LivenessProbe: &core.Probe{
				Handler: core.Handler{
					Exec: probCmds,
				},
				FailureThreshold:    3,
				InitialDelaySeconds: 30,
				PeriodSeconds:       10,
				SuccessThreshold:    1,
				TimeoutSeconds:      5,
			},
			VolumeMounts: []core.VolumeMount{
				{
					Name:      "storage",
					MountPath: "/var/lib/juju",
				},
				{
					Name:      "storage",
					MountPath: "/var/lib/juju/db",
					SubPath:   "db",
				},
				{
					Name:      "juju-controller-test-server-pem",
					MountPath: "/var/lib/juju/template-server.pem",
					SubPath:   "template-server.pem",
					ReadOnly:  true,
				},
				{
					Name:      "juju-controller-test-shared-secret",
					MountPath: "/var/lib/juju/shared-secret",
					SubPath:   "shared-secret",
					ReadOnly:  true,
				},
			},
		},
		{
			Name:            "api-server",
			ImagePullPolicy: core.PullIfNotPresent,
			Image:           "jujusolutions/jujud-operator:" + jujuversion.Current.String(),
			Command: []string{
				"/bin/sh",
			},
			Args: []string{
				"-c",
				`
export JUJU_DATA_DIR=/var/lib/juju
export JUJU_TOOLS_DIR=$JUJU_DATA_DIR/tools

mkdir -p $JUJU_TOOLS_DIR
cp /opt/jujud $JUJU_TOOLS_DIR/jujud

test -e $JUJU_DATA_DIR/agents/machine-0/agent.conf || $JUJU_TOOLS_DIR/jujud bootstrap-state $JUJU_DATA_DIR/bootstrap-params --data-dir $JUJU_DATA_DIR --debug --timeout 10m0s
$JUJU_TOOLS_DIR/jujud machine --data-dir $JUJU_DATA_DIR --machine-id 0 --debug
`[1:],
			},
			WorkingDir: "/var/lib/juju",
			VolumeMounts: []core.VolumeMount{
				{
					Name:      "storage",
					MountPath: "/var/lib/juju",
				},
				{
					Name:      "juju-controller-test-agent-conf",
					MountPath: "/var/lib/juju/agents/machine-0/template-agent.conf",
					SubPath:   "template-agent.conf",
				},
				{
					Name:      "juju-controller-test-server-pem",
					MountPath: "/var/lib/juju/template-server.pem",
					SubPath:   "template-server.pem",
					ReadOnly:  true,
				},
				{
					Name:      "juju-controller-test-shared-secret",
					MountPath: "/var/lib/juju/shared-secret",
					SubPath:   "shared-secret",
					ReadOnly:  true,
				},
				{
					Name:      "juju-controller-test-bootstrap-params",
					MountPath: "/var/lib/juju/bootstrap-params",
					SubPath:   "bootstrap-params",
					ReadOnly:  true,
				},
			},
		},
	}

	podWatcher := s.k8sNewFakeWatcher()
	eventWatcher := s.k8sNewFakeWatcher()
	eventsPartial := &core.EventList{
		Items: []core.Event{
			{
				Type:   core.EventTypeNormal,
				Reason: provider.PullingImage,
			},
			{
				Type:   core.EventTypeNormal,
				Reason: provider.PulledImage,
			},
			{
				InvolvedObject: core.ObjectReference{FieldPath: "spec.containers{mongodb}"},
				Type:           core.EventTypeNormal,
				Reason:         provider.StartedContainer,
				Message:        "Started container mongodb",
			},
		},
	}
	eventsDone := &core.EventList{
		Items: []core.Event{
			{
				Type:   core.EventTypeNormal,
				Reason: provider.PullingImage,
			},
			{
				Type:   core.EventTypeNormal,
				Reason: provider.PulledImage,
			},
			{
				InvolvedObject: core.ObjectReference{FieldPath: "spec.containers{mongodb}"},
				Type:           core.EventTypeNormal,
				Reason:         provider.StartedContainer,
				Message:        "Started container mongodb",
			},
			{
				InvolvedObject: core.ObjectReference{FieldPath: "spec.containers{api-server}"},
				Type:           core.EventTypeNormal,
				Reason:         provider.StartedContainer,
				Message:        "Started container api-server",
			},
		},
	}

	podReady := &core.Pod{
		Status: core.PodStatus{
			Phase: core.PodRunning,
		},
	}

	s.PatchValue(&rand.Reader, bytes.NewReader([]byte{
		0xf0, 0x0d, 0xba, 0xad,
		0x00, 0xff, 0xba, 0xad,
	}))
	s.PatchValue(&jujuversion.GitCommit, "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")
	prepullPodFailSpec := core.Pod{
		ObjectMeta: v1.ObjectMeta{
			Namespace: s.getNamespace(),
			Name:      "operator-image-prepull-f00dbaad",
		},
		Spec: core.PodSpec{
			RestartPolicy: core.RestartPolicyNever,
			Containers: []core.Container{
				core.Container{
					Name:            "jujud",
					Image:           fmt.Sprintf("jujusolutions/jujud-operator-git:%s-0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", jujuversion.Current),
					ImagePullPolicy: core.PullIfNotPresent,
					Command:         []string{"/opt/jujud"},
					Args:            []string{"version"},
				},
			},
		},
	}
	prepullPodFail := prepullPodFailSpec
	prepullPodFail.Status = core.PodStatus{
		Phase: core.PodPending,
		ContainerStatuses: []core.ContainerStatus{
			core.ContainerStatus{
				Name: "jujud",
				State: core.ContainerState{
					Waiting: &core.ContainerStateWaiting{
						Reason: "ImagePullBackOff",
					},
				},
			},
		},
	}
	prepullPodFailWatcher := s.k8sNewFakeWatcher()
	prepullPodSpec := prepullPodFailSpec
	prepullPodSpec.ObjectMeta.Name = "operator-image-prepull-00ffbaad"
	prepullPodSpec.Spec.Containers = []core.Container{
		core.Container{
			Name:            "jujud",
			Image:           fmt.Sprintf("jujusolutions/jujud-operator:%s", jujuversion.Current),
			ImagePullPolicy: core.PullIfNotPresent,
			Command:         []string{"/opt/jujud"},
			Args:            []string{"version"},
		},
	}
	prepullPod := prepullPodSpec
	prepullPod.Status = core.PodStatus{
		Phase: core.PodSucceeded,
	}
	prepullPodWatcher := s.k8sNewFakeWatcher()

	gomock.InOrder(
		// create namespace.
		s.mockNamespaces.EXPECT().Create(ns).Times(1).
			Return(ns, nil),

		// prepull operator image
		s.mockPods.EXPECT().Watch(
			v1.ListOptions{
				FieldSelector:        "metadata.name=operator-image-prepull-f00dbaad",
				Watch:                true,
				IncludeUninitialized: true,
			},
		).
			Return(prepullPodFailWatcher, nil).Times(1),
		s.mockPods.EXPECT().Create(&prepullPodFailSpec).
			Return(&prepullPodFail, nil).Times(1),
		s.mockPods.EXPECT().Delete("operator-image-prepull-f00dbaad", &v1.DeleteOptions{}).
			Return(nil).Times(1),
		s.mockPods.EXPECT().Watch(
			v1.ListOptions{
				FieldSelector:        "metadata.name=operator-image-prepull-00ffbaad",
				Watch:                true,
				IncludeUninitialized: true,
			},
		).
			Return(prepullPodWatcher, nil).Times(1),
		s.mockPods.EXPECT().Create(&prepullPodSpec).
			Return(&prepullPod, nil).Times(1),
		s.mockPods.EXPECT().Delete("operator-image-prepull-00ffbaad", &v1.DeleteOptions{}).
			Return(nil).Times(1),

		// ensure service
		s.mockServices.EXPECT().Get("juju-controller-test-service", v1.GetOptions{IncludeUninitialized: true}).Times(1).
			Return(nil, s.k8sNotFoundError()),
		s.mockServices.EXPECT().Update(svcNotProvisioned).Times(1).
			Return(nil, s.k8sNotFoundError()),
		s.mockServices.EXPECT().Create(svcNotProvisioned).Times(1).
			Return(svcNotProvisioned, nil),

		// below calls are for GetService - 1st address no provisioned yet.
		s.mockServices.EXPECT().List(v1.ListOptions{LabelSelector: "juju-app==juju-controller-test", IncludeUninitialized: true}).Times(1).
			Return(&core.ServiceList{Items: []core.Service{*svcNotProvisioned}}, nil),
		s.mockStatefulSets.EXPECT().Get("juju-operator-juju-controller-test", v1.GetOptions{IncludeUninitialized: true}).Times(1).
			Return(nil, s.k8sNotFoundError()),
		s.mockStatefulSets.EXPECT().Get("juju-controller-test", v1.GetOptions{IncludeUninitialized: false}).Times(1).
			Return(nil, s.k8sNotFoundError()),
		s.mockDeployments.EXPECT().Get("juju-controller-test", v1.GetOptions{IncludeUninitialized: false}).Times(1).
			Return(nil, s.k8sNotFoundError()),

		// below calls are for GetService - 2nd address is ready.
		s.mockServices.EXPECT().List(v1.ListOptions{LabelSelector: "juju-app==juju-controller-test", IncludeUninitialized: true}).Times(1).
			Return(&core.ServiceList{Items: []core.Service{*svcProvisioned}}, nil),
		s.mockStatefulSets.EXPECT().Get("juju-operator-juju-controller-test", v1.GetOptions{IncludeUninitialized: true}).Times(1).
			Return(nil, s.k8sNotFoundError()),
		s.mockStatefulSets.EXPECT().Get("juju-controller-test", v1.GetOptions{IncludeUninitialized: false}).Times(1).
			Return(nil, s.k8sNotFoundError()),
		s.mockDeployments.EXPECT().Get("juju-controller-test", v1.GetOptions{IncludeUninitialized: false}).Times(1).
			Return(nil, s.k8sNotFoundError()),

		// ensure shared-secret secret.
		s.mockSecrets.EXPECT().Get("juju-controller-test-secret", v1.GetOptions{IncludeUninitialized: true}).AnyTimes().
			Return(nil, s.k8sNotFoundError()),
		s.mockSecrets.EXPECT().Create(emptySecret).AnyTimes().
			Return(emptySecret, nil),
		s.mockSecrets.EXPECT().Get("juju-controller-test-secret", v1.GetOptions{IncludeUninitialized: true}).AnyTimes().
			Return(emptySecret, nil),
		s.mockSecrets.EXPECT().Update(secretWithSharedSecretAdded).AnyTimes().
			Return(secretWithSharedSecretAdded, nil),

		// ensure server.pem secret.
		s.mockSecrets.EXPECT().Get("juju-controller-test-secret", v1.GetOptions{IncludeUninitialized: true}).AnyTimes().
			Return(secretWithSharedSecretAdded, nil),
		s.mockSecrets.EXPECT().Update(secretWithServerPEMAdded).AnyTimes().
			Return(secretWithServerPEMAdded, nil),

		// ensure bootstrap-params configmap.
		s.mockConfigMaps.EXPECT().Get("juju-controller-test-configmap", v1.GetOptions{IncludeUninitialized: true}).AnyTimes().
			Return(nil, s.k8sNotFoundError()),
		s.mockConfigMaps.EXPECT().Create(emptyConfigMap).AnyTimes().
			Return(emptyConfigMap, nil),
		s.mockConfigMaps.EXPECT().Get("juju-controller-test-configmap", v1.GetOptions{IncludeUninitialized: true}).AnyTimes().
			Return(emptyConfigMap, nil),
		s.mockConfigMaps.EXPECT().Update(configMapWithBootstrapParamsAdded).AnyTimes().
			Return(configMapWithBootstrapParamsAdded, nil),

		// ensure agent.conf configmap.
		s.mockConfigMaps.EXPECT().Get("juju-controller-test-configmap", v1.GetOptions{IncludeUninitialized: true}).AnyTimes().
			Return(configMapWithBootstrapParamsAdded, nil),
		s.mockConfigMaps.EXPECT().Update(configMapWithAgentConfAdded).AnyTimes().
			Return(configMapWithAgentConfAdded, nil),

		// Check the operator storage exists.
		// first check if <namespace>-<storage-class> exist or not.
		s.mockStorageClass.EXPECT().Get("controller-1-some-storage", v1.GetOptions{}).Times(1).
			Return(nil, s.k8sNotFoundError()),
		// not found, fallback to <storage-class>.
		s.mockStorageClass.EXPECT().Get("some-storage", v1.GetOptions{}).Times(1).
			Return(&sc, nil),

		// ensure statefulset.
		s.mockPods.EXPECT().Watch(
			v1.ListOptions{
				LabelSelector:        "juju-app==juju-controller-test",
				Watch:                true,
				IncludeUninitialized: true,
			},
		).
			Return(podWatcher, nil),
		s.mockStatefulSets.EXPECT().Create(statefulSetSpec).Times(1).
			Return(statefulSetSpec, nil),
		s.mockEvents.EXPECT().Watch(
			v1.ListOptions{
				FieldSelector: "involvedObject.name=controller-0,involvedObject.kind=Pod",
				Watch:         true,
			},
		).
			Return(eventWatcher, nil),
		s.mockEvents.EXPECT().List(
			v1.ListOptions{
				IncludeUninitialized: true,
				FieldSelector:        "involvedObject.name=controller-0,involvedObject.kind=Pod",
			},
		).
			DoAndReturn(func(...interface{}) (*core.EventList, error) {
				eventWatcher.Action(provider.StartedContainer, nil)
				s.clock.WaitAdvance(time.Second, testing.ShortWait, 2)
				return eventsPartial, nil
			}),

		s.mockEvents.EXPECT().List(
			v1.ListOptions{
				IncludeUninitialized: true,
				FieldSelector:        "involvedObject.name=controller-0,involvedObject.kind=Pod",
			},
		).
			DoAndReturn(func(...interface{}) (*core.EventList, error) {
				podWatcher.Action("PodStarted", nil)
				s.clock.WaitAdvance(time.Second, testing.ShortWait, 2)
				return eventsDone, nil
			}),
		s.mockEvents.EXPECT().List(
			v1.ListOptions{
				IncludeUninitialized: true,
				FieldSelector:        "involvedObject.name=controller-0,involvedObject.kind=Pod",
			},
		).
			Return(eventsDone, nil),
		s.mockPods.EXPECT().Get("controller-0", v1.GetOptions{IncludeUninitialized: true}).
			Return(podReady, nil),
	)

	errChan := make(chan error)
	go func() {
		errChan <- controllerStacker.Deploy()
	}()

	err = s.clock.WaitAdvance(3*time.Second, testing.ShortWait, 1)
	c.Assert(err, jc.ErrorIsNil)

	select {
	case err := <-errChan:
		c.Assert(err, jc.ErrorIsNil)
		c.Assert(s.watchers, gc.HasLen, 4)
		c.Assert(workertest.CheckKilled(c, s.watchers[0]), jc.ErrorIsNil)
		c.Assert(workertest.CheckKilled(c, s.watchers[1]), jc.ErrorIsNil)
		c.Assert(workertest.CheckKilled(c, s.watchers[2]), jc.ErrorIsNil)
		c.Assert(workertest.CheckKilled(c, s.watchers[3]), jc.ErrorIsNil)
		c.Assert(podWatcher.IsStopped(), jc.IsTrue)
		c.Assert(eventWatcher.IsStopped(), jc.IsTrue)
		c.Assert(prepullPodFailWatcher.IsStopped(), jc.IsTrue)
		c.Assert(prepullPodWatcher.IsStopped(), jc.IsTrue)
	case <-time.After(coretesting.LongWait):
		c.Fatalf("timed out waiting for deploy return")
	}
}
