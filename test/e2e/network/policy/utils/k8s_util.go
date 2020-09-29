package utils

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"k8s.io/client-go/rest"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	v1net "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

type Kubernetes struct {
	mutex     *sync.Mutex
	podCache  map[string][]v1.Pod
	ClientSet *kubernetes.Clientset
}

//NewKubernetes is a utility function that wraps creation of the Kube client.
func NewKubernetes() (*Kubernetes, error) {
	clientSet, err := Client()
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to instantiate kube client")
	}
	return &Kubernetes{
		mutex:     &sync.Mutex{},
		podCache:  map[string][]v1.Pod{},
		ClientSet: clientSet,
	}, nil
}

// GetPod returns a pod with the matching namespace and name
func (k *Kubernetes) GetPod(ns string, name string) (*v1.Pod, error) {
	pods, err := k.getPodsUncached(ns, "pod", name)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to get pod %s/%s", ns, name)
	}
	if len(pods) == 0 {
		return nil, nil
	}
	return &pods[0], nil
}

func (k *Kubernetes) getPodsUncached(ns string, key, val string) ([]v1.Pod, error) {
	v1PodList, err := k.ClientSet.CoreV1().Pods(ns).List(context.TODO(), metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%v=%v", key, val),
	})
	if err != nil {
		return nil, errors.WithMessage(err, "unable to list Pods")
	}
	return v1PodList.Items, nil
}

// GetPods returns an array of all Pods in the given namespace having a k/v label pair.
func (k *Kubernetes) GetPods(ns string, key string, val string) ([]v1.Pod, error) {

	if p, ok := k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)]; ok {
		return p, nil
	}

	v1PodList, err := k.getPodsUncached(ns, key, val)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to list Pods")
	}
	k.mutex.Lock()
	k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)] = v1PodList
	k.mutex.Unlock()
	return v1PodList, nil
}

// Probe execs into a pod and checks its connectivity to another pod.  Of course it assumes
// that the target pod is serving on the input port, and also that wget is installed.  For perf it uses
// spider rather then actually getting the full contents.
func (k *Kubernetes) Probe(ns1 string, pod1 string, ns2 string, pod2 string, protocol v1.Protocol, fromPort int, toPort int) (bool, error, string) {
	fromPods, err := k.GetPods(ns1, "pod", pod1)
	if err != nil {
		return false, errors.WithMessagef(err, "unable to get Pods from ns %s", ns1), ""
	}
	if len(fromPods) == 0 {
		return false, errors.New(fmt.Sprintf("no pod of name %s in namespace %s found", pod1, ns1)), ""
	}
	fromPod := fromPods[0]

	toPods, err := k.GetPods(ns2, "pod", pod2)
	if err != nil {
		return false, errors.WithMessagef(err, "unable to get Pods from ns %s", ns2), ""
	}
	if len(toPods) == 0 {
		return false, errors.New(fmt.Sprintf("no pod of name %s in namespace %s found", pod2, ns2)), ""
	}
	toPod := toPods[0]

	toIP := toPod.Status.PodIP

	// There seems to be an issue when running Antrea in Kind where tunnel traffic is dropped at
	// first. This leads to the first test being run consistently failing. To avoid this issue
	// until it is resolved, we try to connect 3 times.
	// See https://github.com/vmware-tanzu/antrea/issues/467.
	cmd := []string{
		"/bin/sh",
		"-c",
		// 3 tries, timeout is 1 second
		// it uses the identical port for send and receive traffic.  TODO possibly support different ports.

		// fmt.Sprintf("for i in $(seq 1 3); do ncat -p %d -vz -w 1 %s %d && exit 0 || true; done; exit 1", fromPort, toIP, toPort),
	}

	var protocolString string
	switch protocol {
	case v1.ProtocolSCTP:
		cmd = append(cmd, fmt.Sprintf("for i in $(seq 1 3); do ncat --sctp -p %d -vz -w 1 %s %d && exit 0 || true; done; exit 1", fromPort, toIP, toPort))
		protocolString = "sctp"
	case v1.ProtocolTCP:
		// TODO add a retry if necessary
		cmd = append(cmd, fmt.Sprintf("ncat -p %d -v -z -w 1 %s %d && exit 0 || exit 1", fromPort, toIP, toPort))
		protocolString = "tcp"
	case v1.ProtocolUDP:
		cmd = append(cmd, fmt.Sprintf("ncat -u -p %d -v -z -w 1 %s %d && exit 0 || exit 1", fromPort, toIP, toPort))
		protocolString = "udp"
	default:
		panic(errors.Errorf("protocol %s not supported", protocol))
	}
	// HACK: inferring container name as c80, c81, etc, for simplicity.
	// TODO this is indirectly coupled to the deployment name -- this connection should be made explicitly
	containerName := fmt.Sprintf("c%v-%v", toPort, protocolString)
	theCommand := fmt.Sprintf("kubectl exec %s -c %s -n %s -- %s", fromPod.Name, containerName, fromPod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.ExecuteRemoteCommand(fromPod, containerName, cmd)
	if err != nil {
		// log this error as trace since may be an expected failure
		log.Infof("%s/%s -> %s/%s: error when running command: err - %v /// stdout - %s /// stderr - %s", ns1, pod1, ns2, pod2, err, stdout, stderr)
		// do not return an error
		return false, nil, theCommand
	}
	return true, nil, theCommand
}

// ExecuteRemoteCommand executes a remote shell command on the given pod
// returns the output from stdout and stderr
func (k *Kubernetes) ExecuteRemoteCommand(pod v1.Pod, cname string, command []string) (string, string, error) {
	kubeCfg := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)
	restCfg, err := kubeCfg.ClientConfig()
	if err != nil {
		return "", "", errors.WithMessagef(err, "unable to get rest config from kube config")
	}
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	request := k.ClientSet.CoreV1().RESTClient().Post().Namespace(pod.Namespace).Resource("Pods").
		Name(pod.Name).SubResource("exec").VersionedParams(&v1.PodExecOptions{
		Container: cname,
		Command:   command,
		Stdin:     false,
		Stdout:    true,
		Stderr:    true,
		TTY:       false},
		scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restCfg, "POST", request.URL())
	if err != nil {
		return "", "", errors.Wrapf(err, "failed to create SPDYExecutor")
	}
	err = exec.Stream(remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	})
	if err != nil {
		return buf.String(), errBuf.String(), err
	}
	return buf.String(), errBuf.String(), nil
}

func Client() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(
			os.Getenv("HOME"), ".kube", "config",
		)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, errors.WithMessagef(err, "unable to build config from flags, check that your KUBECONFIG file is correct !")
		}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to instantiate clientset")
	}
	return clientset, nil
}

// CreateOrUpdateNamespace is a convenience function for idempotent setup of Namespaces
func (k *Kubernetes) CreateOrUpdateNamespace(n string, labels map[string]string) (*v1.Namespace, error) {
	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   n,
			Labels: labels,
		},
	}
	nsr, err := k.ClientSet.CoreV1().Namespaces().Create(context.TODO(), ns, metav1.CreateOptions{})
	if err == nil {
		log.Infof("created namespace %s", n)
		return nsr, nil
	}

	log.Debugf("unable to create namespace %s, let's try updating it instead (error: %s)", ns.Name, err)
	nsr, err = k.ClientSet.CoreV1().Namespaces().Update(context.TODO(), ns, metav1.UpdateOptions{})
	if err != nil {
		log.Debugf("unable to update namespace %s: %s", ns, err)
	}

	return nsr, err
}

func makeContainerSpec(port int32, protocol v1.Protocol) v1.Container {
	var cmd []string
	var protocolString string

	switch protocol {
	case v1.ProtocolTCP:
		cmd = []string{"ncat", "-l", "-k", "-p", fmt.Sprintf("%d", port)}
		protocolString = "tcp"
	case v1.ProtocolUDP:
		cmd = []string{"ncat", "-u", "-l", "-p", fmt.Sprintf("%d", port)}
		protocolString = "udp"
	case v1.ProtocolSCTP:
		cmd = []string{"ncat", "--sctp", "-l", "-k", "-p", fmt.Sprintf("%d", port)}
		protocolString = "sctp"
	default:
		panic(errors.Errorf("invalid protocol %s", protocol))
	}

	return v1.Container{
		Name:            fmt.Sprintf("c%d-%s", port, protocolString),
		ImagePullPolicy: v1.PullIfNotPresent,
		Image:           "antrea/netpol-test:latest",
		// "-k" for persistent server
		Command:         cmd,
		SecurityContext: &v1.SecurityContext{},
		Ports: []v1.ContainerPort{
			{
				ContainerPort: port,
				Name:          fmt.Sprintf("serve-%d-%s", port, protocolString),
				Protocol:      protocol,
			},
		},
	}
}

// CreateOrUpdateDeployment is a convenience function for idempotent setup of deployments
func (k *Kubernetes) CreateOrUpdateDeployment(ns, deploymentName string, replicas int32, labels map[string]string) (*appsv1.Deployment, error) {
	zero := int64(0)
	log.Infof("creating/updating deployment %s in ns %s", deploymentName, ns)

	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      deploymentName,
			Labels:    labels,
			Namespace: ns,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{MatchLabels: labels},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:    labels,
					Namespace: ns,
				},
				Spec: v1.PodSpec{
					TerminationGracePeriodSeconds: &zero,
					Containers: []v1.Container{
						makeContainerSpec(80, v1.ProtocolTCP), makeContainerSpec(81, v1.ProtocolTCP),
						makeContainerSpec(80, v1.ProtocolUDP), makeContainerSpec(81, v1.ProtocolUDP),
						makeContainerSpec(80, v1.ProtocolSCTP), makeContainerSpec(81, v1.ProtocolSCTP),
					},
				},
			},
		},
	}

	d, err := k.ClientSet.AppsV1().Deployments(ns).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err == nil {
		log.Infof("created deployment %s in namespace %s", d.Name, ns)
		return d, nil
	}

	log.Debugf("unable to create deployment %s in ns %s, let's try update instead", deployment.Name, ns)
	d, err = k.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), d, metav1.UpdateOptions{})
	if err != nil {
		//bytes, marshalErr := json.MarshalIndent(deployment, "", "  ")
		//if marshalErr != nil { panic(marshalErr) }
		//log.Errorf("unable to create/update deployment %s/%s: %+v\n\n%s", ns, deployment.Name, err, bytes)
		log.Errorf("unable to create/update deployment %s/%s: %+v", ns, deployment.Name, err)
	}

	return d, errors.Wrapf(err, "unable to update deployment %s/%s", ns, deployment.Name)
}

// CleanNetworkPolicies is a convenience function for deleting network policies before startup of any new test.
func (k *Kubernetes) CleanNetworkPolicies(namespaces []string) error {
	for _, ns := range namespaces {
		log.Infof("deleting policies..........%v ", ns)
		l, err := k.ClientSet.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
		if err != nil {
			return errors.Wrapf(err, "unable to list network policies in ns %s", ns)
		}
		for _, np := range l.Items {
			log.Infof("deleting network policy %s in ns %s", np.Name, ns)
			err = k.ClientSet.NetworkingV1().NetworkPolicies(ns).Delete(context.TODO(), np.Name, metav1.DeleteOptions{})
			if err != nil {
				return errors.Wrapf(err, "unable to delete network policy %s", np.Name)
			}
		}
	}
	return nil
}

func (k *Kubernetes) ClearCache() {
	log.Info("Clearing pod cache...")
	k.mutex.Lock()
	k.podCache = map[string][]v1.Pod{}
	k.mutex.Unlock()
}

// CreateOrUpdateNetworkPolicy is a convenience function for updating/creating netpols. Updating is important since
// some tests update a network policy to confirm that mutation works with a CNI.
func (k *Kubernetes) CreateOrUpdateNetworkPolicy(ns string, netpol *v1net.NetworkPolicy) (*v1net.NetworkPolicy, error) {
	log.Infof("creating/updating network policy %s in ns %s", netpol.Name, ns)
	netpol.ObjectMeta.Namespace = ns
	np, err := k.ClientSet.NetworkingV1().NetworkPolicies(ns).Update(context.TODO(), netpol, metav1.UpdateOptions{})
	if err == nil {
		return np, err
	}

	log.Debugf("unable to update network policy %s in ns %s, let's try creating it instead (error: %s)", netpol.Name, ns, err)
	np, err = k.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), netpol, metav1.CreateOptions{})
	if err != nil {
		log.Debugf("unable to create network policy: %s", err)
	}
	return np, err
}

// Bootstrap checks the state of the cluster, and if necessary:
// - creates namespaces
// - creates deployments
// - waits for pods to come up
func (k *Kubernetes) Bootstrap(namespaces []string, pods []string, allPods []PodString) error {
	for _, ns := range namespaces {
		_, err := k.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		if err != nil {
			return errors.WithMessagef(err, "unable to create/update ns %s", ns)
		}

		for _, pod := range pods {
			log.Infof("creating/updating pod %s/%s", ns, pod)
			_, err := k.CreateOrUpdateDeployment(ns, ns+pod, 1, map[string]string{"pod": pod})
			if err != nil {
				return errors.WithMessagef(err, "unable to create/update deployment %s/%s", ns, pod)
			}
		}
	}

	for _, pod := range allPods {
		err := waitForPodInNamespace(k, pod.Namespace(), pod.PodName())
		if err != nil {
			return errors.WithMessagef(err, "unable to wait for pod %s/%s", pod.Namespace(), pod.PodName())
		}
	}

	// Ensure that all the HTTP servers have time to start properly.
	// See https://github.com/vmware-tanzu/antrea/issues/472.
	if err := waitForHTTPServers(k); err != nil {
		return err
	}

	return nil
}
