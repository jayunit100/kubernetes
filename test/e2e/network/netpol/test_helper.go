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
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/onsi/ginkgo"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

var (
	// NetpolTestPods are the pod + deployment names used for connectivity probes
	NetpolTestPods = []string{"a", "b", "c"}
	// NetpolTestNamespaces are the namespaces used for connectivity probes
	NetpolTestNamespaces = []string{"x", "y", "z"}
)

// GetAllPods returns a cartesian product of test namespaces and test pods
func GetAllPods() []PodString {
	var allPods []PodString
	for _, podName := range NetpolTestPods {
		for _, ns := range NetpolTestNamespaces {
			allPods = append(allPods, NewPodString(ns, podName))
		}
	}
	return allPods
}

// prettyPrint a networkPolicy
func jsonPrettyPrint(policy *networkingv1.NetworkPolicy) string {
	raw, _ := json.MarshalIndent(policy, "", "\t")
	return string(raw)
}

// CreateOrUpdatePolicy fails if it can not create or update the policy in the given namespace
func CreateOrUpdatePolicy(k8s *Kubernetes, policy *networkingv1.NetworkPolicy, namespace string, isVerbose bool) {
	if isVerbose {
		fmt.Println("****************************************************************")
		framework.Logf("Network Policy creating %s/%s %v", namespace, policy.Name, jsonPrettyPrint(policy))
		fmt.Println("****************************************************************")
	}

	_, err := k8s.CreateOrUpdateNetworkPolicy(namespace, policy)
	framework.ExpectNoError(err, "Unable to create/update netpol %s/%s", namespace, policy.Name)
}

// CleanPolicies removes network policies
func CleanPolicies(k8s *Kubernetes, namespaces []string) {
	err := k8s.CleanNetworkPolicies(namespaces)
	framework.ExpectNoError(err, "Error occurred while cleaning network policy")
}

// ValidateOrFail validates connectivity
func ValidateOrFail(k8s *Kubernetes, testCase *NetpolTestCase, isVerbose bool) {
	ginkgo.By("Validating reachability matrix...")

	ProbePodToPodConnectivity(k8s, testCase)
	if _, wrong, _ := testCase.Reachability.Summary(); wrong != 0 {
		testCase.Reachability.PrintSummary(true, true, true)
		framework.Failf("Had %d wrong results in reachability matrix", wrong)
	} else {
		if isVerbose {
			testCase.Reachability.PrintSummary(true, true, true)
		}
		fmt.Println("VALIDATION SUCCESSFUL")
	}
}

// ResetNamespaceLabels returns a namespace's labels to their original state
func ResetNamespaceLabels(f *framework.Framework, ns string) {
	selectedNameSpace, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get namespace %v", ns)
	selectedNameSpace.ObjectMeta.Labels = map[string]string{"ns": ns}
	_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update Namespace %v", ns)
	time.Sleep(10 * time.Second)
}

// ResetDeploymentPodLabels returns a deployment's spec labels to their original state
func ResetDeploymentPodLabels(f *framework.Framework, ns string, pod string) {
	deployment, err := f.ClientSet.AppsV1().Deployments(ns).Get(context.TODO(), ns+pod, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get deployment %s/%s", ns, pod)
	deployment.Spec.Template.ObjectMeta.Labels = map[string]string{"pod": pod}
	_, err = f.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update deployment %s/%s labels", ns, pod)
	time.Sleep(10 * time.Second)
}

// UpdateNamespaceLabels sets the labels for a namespace
func UpdateNamespaceLabels(f *framework.Framework, ns string, newNsLabel map[string]string) {
	selectedNameSpace, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get namespace %v", ns)
	selectedNameSpace.ObjectMeta.Labels = newNsLabel
	_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update Label of namespace %v", ns)
	time.Sleep(10 * time.Second)
}

// AddDeploymentPodLabels adds new labels to a deployment's template
func AddDeploymentPodLabels(f *framework.Framework, ns string, pod string, newPodLabels map[string]string) {
	deployment, err := f.ClientSet.AppsV1().Deployments(ns).Get(context.TODO(), ns+pod, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get deployment %s/%s", ns, pod)
	for key, val := range newPodLabels {
		deployment.Spec.Template.ObjectMeta.Labels[key] = val
	}
	_, err = f.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to add deployment %s/%s labels", ns, pod)
	time.Sleep(10 * time.Second)
}
