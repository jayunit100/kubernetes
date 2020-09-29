package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	v1 "k8s.io/api/core/v1"

	"github.com/onsi/ginkgo"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

var (
	NetpolTestPods       = []string{"a", "b", "c"}
	NetpolTestNamespaces = []string{"x", "y", "z"}
)

func GetAllPods() []PodString {
	var allPods []PodString
	for _, podName := range NetpolTestPods {
		for _, ns := range NetpolTestNamespaces {
			allPods = append(allPods, NewPodString(ns, podName))
		}
	}
	return allPods
}

type Scenario struct {
	Pods       []string
	Namespaces []string
	P80        int
	P81        int
	AllPods    []PodString
	//policies   []networkingv1.NetworkPolicy
}

// NewScenario creates a new test scenario.
func NewScenario() *Scenario {
	return &Scenario{
		Pods:       NetpolTestPods,
		Namespaces: NetpolTestNamespaces,
		P80:        80,
		P81:        81,
		AllPods:    GetAllPods(),
	}
}

// prettyPrint a networkPolicy
func jsonPrettyPrint(policy *networkingv1.NetworkPolicy) string {
	raw, _ := json.Marshal(policy)
	var out bytes.Buffer
	err := json.Indent(&out, []byte(raw), "", "\t")
	if err != nil {
		return ""
	}
	return out.String()
}

func CleanPoliciesAndValidate(f *framework.Framework, k8s *Kubernetes, scenario *Scenario, protocol v1.Protocol) {
	err := k8s.CleanNetworkPolicies(scenario.Namespaces)
	framework.ExpectNoError(err, "Error occurred while cleaning network policy")
	reachability := NewReachability(scenario.AllPods, true)
	ValidateOrFailFuncInner(k8s, f, "x", protocol, 83, 80, nil, reachability, false, scenario, false)
}

func ValidateOrFailFunc(k8s *Kubernetes, f *framework.Framework, ns string, protocol v1.Protocol, fromPort, toPort int, policy *networkingv1.NetworkPolicy,
	reachability *Reachability, cleanPreviousPolicies bool, scenario *Scenario) {
	ValidateOrFailFuncInner(k8s, f, ns, protocol, fromPort, toPort, policy, reachability, cleanPreviousPolicies, scenario, false)
}

func ValidateOrFailFuncInner(k8s *Kubernetes, f *framework.Framework, ns string, protocol v1.Protocol, fromPort, toPort int, policy *networkingv1.NetworkPolicy,
	reachability *Reachability, cleanPreviousPolicies bool, scenario *Scenario, quiet bool) {
	if cleanPreviousPolicies {
		err := k8s.CleanNetworkPolicies(scenario.Namespaces)
		framework.ExpectNoError(err, "Error occurred while cleaning network policy")
	}

	if policy != nil {

		fmt.Println("****************************************************************")
		framework.Logf("Network Policy creating %v %v", policy.Name, jsonPrettyPrint(policy))
		fmt.Println("****************************************************************")
		_, err1 := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), policy, metav1.CreateOptions{})
		if err1 != nil {
			fmt.Println("Network Policy failed to create, trying to update... ", policy.Name)
			_, err2 := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Update(context.TODO(), policy, metav1.UpdateOptions{})
			if err2 != nil {
				framework.Failf("Network Policy failed CREATING and UPDATING .... %v .... %v", err1, err2)
			}
		}
	}
	ginkgo.By("Validating reachability matrix...")

	Validate(k8s, reachability, fromPort, toPort, protocol)
	if _, wrong, _ := reachability.Summary(); wrong != 0 {
		reachability.PrintSummary(true, true, true)
		framework.Failf("Had more than 0 wrong results in the reachability matrix")
	} else {
		if !quiet {
			reachability.PrintSummary(true, true, true)
		}
		fmt.Println("VALIDATION SUCCESSFUL")
	}
}

func NSLabelCleaner(f *framework.Framework, ns string) {
	selectedNameSpace, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get namespace %v", ns)
	selectedNameSpace.ObjectMeta.Labels = map[string]string{"ns": ns}
	_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update Namespace %v", ns)
	time.Sleep(10 * time.Second)
}

func PodLabelCleaner(f *framework.Framework, ns string, pod string) {
	selectedPod, err := f.ClientSet.AppsV1().Deployments(ns).Get(context.TODO(), ns+pod, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get pod %v in namespace %v", pod, ns)
	selectedPod.Spec.Template.ObjectMeta.Labels = map[string]string{"pod": pod}
	_, err = f.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), selectedPod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update pod %v labels in namespace %v", pod, ns)
	time.Sleep(10 * time.Second)
}

func NSLabelUpdater(f *framework.Framework, ns string, newNsLabel map[string]string) {
	selectedNameSpace, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get namespace %v", ns)
	selectedNameSpace.ObjectMeta.Labels = newNsLabel
	_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update Label of namespace %v", ns)
	time.Sleep(10 * time.Second)
}

func PodLabelUpdater(f *framework.Framework, ns string, pod string, newPodLabel map[string]string) {
	selectedPod, err := f.ClientSet.AppsV1().Deployments(ns).Get(context.TODO(), ns+pod, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get pod %v in namespace %v", pod, ns)
	selectedPod.Spec.Template.ObjectMeta.Labels = newPodLabel
	_, err = f.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), selectedPod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update pod %v labels in namespace %v", pod, ns)
	time.Sleep(10 * time.Second)
}
