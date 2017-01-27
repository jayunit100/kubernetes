package app

import (
	"fmt"
	"io/ioutil"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/plugin/pkg/scheduler"
	schedulerapi "k8s.io/kubernetes/plugin/pkg/scheduler/api"
	latestschedulerapi "k8s.io/kubernetes/plugin/pkg/scheduler/api/latest"

	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/client/clientset_generated/clientset"
	"k8s.io/kubernetes/plugin/cmd/kube-scheduler/app/options"

	"github.com/golang/glog"
	v1core "k8s.io/kubernetes/pkg/client/clientset_generated/clientset/typed/core/v1"
	"k8s.io/kubernetes/pkg/client/record"
	"k8s.io/kubernetes/plugin/pkg/scheduler/factory"
)

func createRecorder(kubecli *clientset.Clientset, s *options.SchedulerServer) record.EventRecorder {
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: kubecli.Core().Events("")})
	return eventBroadcaster.NewRecorder(v1.EventSource{Component: s.SchedulerName})
}

func createClient(s *options.SchedulerServer) (*clientset.Clientset, error) {
	kubeconfig, err := clientcmd.BuildConfigFromFlags(s.Master, s.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("unable to build config from flags: %v", err)
	}

	kubeconfig.ContentType = s.ContentType
	// Override kubeconfig qps/burst settings from flags
	kubeconfig.QPS = s.KubeAPIQPS
	kubeconfig.Burst = int(s.KubeAPIBurst)

	cli, err := clientset.NewForConfig(restclient.AddUserAgent(kubeconfig, "leader-election"))
	if err != nil {
		return nil, fmt.Errorf("invalid API configuration: %v", err)
	}
	return cli, nil
}

// createScheduler encapsulates the entire creation of a runnable scheduler.
func createScheduler(s *options.SchedulerServer, kubecli *clientset.Clientset, recorder record.EventRecorder) (*scheduler.Scheduler, error) {
	configurator := factory.NewConfigFactory(kubecli, s.SchedulerName, s.HardPodAffinitySymmetricWeight, s.FailureDomains)

	// Rebuild the configurator with a default Create(...) method.
	configurator = &schedulerConfigurator{
		configurator,
		s.PolicyConfigFile,
		s.AlgorithmProvider}

	return scheduler.NewFromConfigurator(configurator, func(cfg *scheduler.Config) {
		cfg.Recorder = recorder
	})
}

// schedulerConfigurator is an interface wrapper that provides default Configuration creation based on user
// provided config file.
type schedulerConfigurator struct {
	scheduler.Configurator
	policyFile        string
	algorithmProvider string
}

func (sc schedulerConfigurator) Create() (*scheduler.Config, error) {
	if _, err := os.Stat(sc.policyFile); err != nil {
		return sc.Configurator.CreateFromProvider(sc.algorithmProvider)
	}

	// policy file is valid, try to create a configuration from it.
	var policy schedulerapi.Policy
	configData, err := ioutil.ReadFile(sc.policyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to read policy config: %v", err)
	}
	if err := runtime.DecodeInto(latestschedulerapi.Codec, configData, &policy); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}
	return sc.CreateFromConfig(policy)
}
