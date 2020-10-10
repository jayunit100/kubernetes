/*
Copyright 2020 The Kubernetes Authors.

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

package netpol

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	imageutils "k8s.io/kubernetes/test/utils/image"
)

// Kubernetes provides a convenience interface to kube functionality
type Kubernetes struct {
	mutex     *sync.Mutex
	podCache  map[string][]v1.Pod
	ClientSet clientset.Interface
}

//NewKubernetes is a utility function that wraps creation of the Kube client.
func NewKubernetes(clientSet clientset.Interface) *Kubernetes {
	return &Kubernetes{
		mutex:     &sync.Mutex{},
		podCache:  map[string][]v1.Pod{},
		ClientSet: clientSet,
	}
}

// InitializeCluster checks the state of the cluster, creating or updating namespaces and deployments as needed
func (k *Kubernetes) InitializeCluster(namespaces []string, pods []string, allPods []PodString, addSCTPContainers bool) error {
	for _, ns := range namespaces {
		_, err := k.CreateOrUpdateNamespace(ns, map[string]string{"ns": ns})
		if err != nil {
			return errors.WithMessagef(err, "unable to create/update ns %s", ns)
		}

		for _, pod := range pods {
			log.Infof("creating/updating pod %s/%s", ns, pod)
			_, err := k.CreateOrUpdateDeployment(ns, ns+pod, 1, map[string]string{"pod": pod}, addSCTPContainers)
			if err != nil {
				return errors.WithMessagef(err, "unable to create/update deployment %s/%s", ns, pod)
			}
		}
	}

	for _, pod := range allPods {
		err := k.waitForPodInNamespace(pod.Namespace(), pod.PodName())
		if err != nil {
			return errors.WithMessagef(err, "unable to wait for pod %s/%s", pod.Namespace(), pod.PodName())
		}
	}

	return k.waitForHTTPServers()
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
	k.mutex.Lock()
	p, ok := k.podCache[fmt.Sprintf("%v_%v_%v", ns, key, val)]
	k.mutex.Unlock()
	if ok {
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

// Probe execs into a pod and checks its connectivity to another pod.
func (k *Kubernetes) Probe(ns1 string, pod1 string, ns2 string, pod2 string, protocol v1.Protocol, fromPort int, toPort int) (bool, string, error) {
	fromPods, err := k.GetPods(ns1, "pod", pod1)
	if err != nil {
		return false, "", errors.WithMessagef(err, "unable to get Pods from ns %s", ns1)
	}
	if len(fromPods) == 0 {
		return false, "", errors.New(fmt.Sprintf("no pod of name %s in namespace %s found", pod1, ns1))
	}
	fromPod := fromPods[0]

	toPods, err := k.GetPods(ns2, "pod", pod2)
	if err != nil {
		return false, "", errors.WithMessagef(err, "unable to get Pods from ns %s", ns2)
	}
	if len(toPods) == 0 {
		return false, "", errors.New(fmt.Sprintf("no pod of name %s in namespace %s found", pod2, ns2))
	}
	toPod := toPods[0]

	toIP := toPod.Status.PodIP

	var cmd []string

	switch protocol {
	case v1.ProtocolSCTP:
		cmd = []string{"/agnhost", "connect", fmt.Sprintf("%s:%d", toIP, toPort), "--timeout=1s", "--protocol=sctp"}
	case v1.ProtocolTCP:
		cmd = []string{"/agnhost", "connect", fmt.Sprintf("%s:%d", toIP, toPort), "--timeout=1s", "--protocol=tcp"}
	case v1.ProtocolUDP:
		cmd = []string{"nc", "-v", "-z", "-w", "1", "-u", toIP, fmt.Sprintf("%d", toPort)}
	default:
		panic(errors.Errorf("protocol %s not supported", protocol))
	}
	containerName := fmt.Sprintf("c%v-%v", toPort, strings.ToLower(string(protocol)))
	commandDebugString := fmt.Sprintf("kubectl exec %s -c %s -n %s -- %s", fromPod.Name, containerName, fromPod.Namespace, strings.Join(cmd, " "))
	stdout, stderr, err := k.ExecuteRemoteCommand(fromPod, containerName, cmd)
	if err != nil {
		log.Infof("%s/%s -> %s/%s: error when running command: err - %v /// stdout - %s /// stderr - %s", ns1, pod1, ns2, pod2, err, stdout, stderr)
		return false, commandDebugString, nil
	}
	return true, commandDebugString, nil
}

// ExecuteRemoteCommand executes a remote shell command on the given pod. Will be replaced with something from framework...
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
	var (
		// agnHostImage is the image URI of AgnHost
		agnHostImage = imageutils.GetE2EImage(imageutils.Agnhost)
		cmd          []string
	)

	switch protocol {
	case v1.ProtocolTCP:
		cmd = []string{"/agnhost", "serve-hostname", "--tcp", "--http=false", "--port", fmt.Sprintf("%d", port)}
	case v1.ProtocolUDP:
		cmd = []string{"/agnhost", "serve-hostname", "--udp", "--http=false", "--port", fmt.Sprintf("%d", port)}
	case v1.ProtocolSCTP:
		cmd = []string{"/agnhost", "netexec", "--sctp-port", fmt.Sprintf("%d", port)}
	default:
		panic(errors.Errorf("invalid protocol %v", protocol))
	}
	return v1.Container{
		Name:            fmt.Sprintf("c%d-%s", port, strings.ToLower(string(protocol))),
		ImagePullPolicy: v1.PullIfNotPresent,
		Image:           agnHostImage,
		Command:         cmd,
		SecurityContext: &v1.SecurityContext{},
		Ports: []v1.ContainerPort{
			{
				ContainerPort: port,
				Name:          fmt.Sprintf("serve-%d-%s", port, strings.ToLower(string(protocol))),
				Protocol:      protocol,
			},
		},
	}
}

// CreateOrUpdateDeployment is a convenience function for idempotent setup of deployments
func (k *Kubernetes) CreateOrUpdateDeployment(ns, deploymentName string, replicas int32, labels map[string]string, addSCTPContainers bool) (*appsv1.Deployment, error) {
	zero := int64(0)
	log.Infof("creating/updating deployment %s in ns %s", deploymentName, ns)

	containers := []v1.Container{
		makeContainerSpec(80, v1.ProtocolTCP),
		makeContainerSpec(81, v1.ProtocolTCP),
		makeContainerSpec(80, v1.ProtocolUDP),
		makeContainerSpec(81, v1.ProtocolUDP),
	}

	if addSCTPContainers {
		containers = append(containers,
			makeContainerSpec(80, v1.ProtocolSCTP),
			makeContainerSpec(81, v1.ProtocolSCTP))
	}

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
					Containers:                    containers,
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

// ClearCache clears the kube pod cache
func (k *Kubernetes) ClearCache() {
	log.Info("Clearing pod cache")
	k.mutex.Lock()
	k.podCache = map[string][]v1.Pod{}
	k.mutex.Unlock()
	log.Info("Pod cache successfully cleared")
}

// CreateOrUpdateNetworkPolicy is a convenience function for updating/creating netpols
func (k *Kubernetes) CreateOrUpdateNetworkPolicy(ns string, netpol *networkingv1.NetworkPolicy) (*networkingv1.NetworkPolicy, error) {
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

func (k *Kubernetes) waitForHTTPServers() error {
	const maxTries = 10
	const sleepInterval = 1 * time.Second
	log.Infof("waiting for HTTP servers (ports 80 and 81) to become ready")
	testCases := map[string]*TestCase{
		"82->80,TCP": {FromPort: 82, ToPort: 80, Protocol: v1.ProtocolTCP},
		"82->81,TCP": {FromPort: 82, ToPort: 81, Protocol: v1.ProtocolTCP},
		"82->80,UDP": {FromPort: 82, ToPort: 80, Protocol: v1.ProtocolUDP},
		"82->81,UDP": {FromPort: 82, ToPort: 81, Protocol: v1.ProtocolUDP},
	}
	notReady := map[string]bool{}
	for caseName := range testCases {
		notReady[caseName] = true
	}
	for i := 0; i < maxTries; i++ {
		for caseName, testCase := range testCases {
			if notReady[caseName] {
				reachability := NewReachability(GetAllPods(), true)
				testCase.Reachability = reachability
				ProbePodToPodConnectivity(k, testCase)
				_, wrong, _ := reachability.Summary()
				if wrong == 0 {
					log.Infof("server %s is ready", caseName)
					delete(notReady, caseName)
				} else {
					log.Infof("server %s is not ready", caseName)
				}
			}
		}
		if len(notReady) == 0 {
			return nil
		}
		time.Sleep(sleepInterval)
	}
	return errors.Errorf("after %d tries, %d HTTP servers are not ready", maxTries, len(notReady))
}

func (k *Kubernetes) waitForPodInNamespace(ns string, pod string) error {
	log.Infof("waiting for pod %s/%s", ns, pod)
	for {
		k8sPod, err := k.GetPod(ns, pod)
		if err != nil {
			return errors.WithMessagef(err, "unable to get pod %s/%s", ns, pod)
		}

		if k8sPod != nil && k8sPod.Status.Phase == v1.PodRunning {
			if k8sPod.Status.PodIP == "" {
				return errors.Errorf("unable to get IP of pod %s/%s", ns, pod)
			}

			log.Debugf("IP of pod %s/%s is: %s", ns, pod, k8sPod.Status.PodIP)

			log.Debugf("pod running: %s/%s", ns, pod)
			return nil
		}
		log.Infof("pod %s/%s not ready, waiting ...", ns, pod)
		time.Sleep(2 * time.Second)
	}
}

func (k *Kubernetes) setNamespaceLabels(ns string, labels map[string]string) error {
	selectedNameSpace, err := k.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	if err != nil {
		return errors.Wrapf(err, "unable to get namespace %s", ns)
	}
	selectedNameSpace.ObjectMeta.Labels = labels
	_, err = k.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	return errors.Wrapf(err, "unable to update namespace %s", ns)
}
