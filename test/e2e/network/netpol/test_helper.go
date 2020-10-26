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
	"github.com/onsi/ginkgo"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/kubernetes/test/e2e/framework"
	"sigs.k8s.io/yaml"
	"time"
)

// prettyPrint a networkPolicy
func prettyPrint(policy *networkingv1.NetworkPolicy) string {
	raw, err := yaml.Marshal(policy)
	framework.ExpectNoError(err, "marshal network policy to yaml")
	return string(raw)
}

// CreateOrUpdatePolicy fails if it can not create or update the policy in the given namespace
func CreateOrUpdatePolicy(k8s *Kubernetes, policy *networkingv1.NetworkPolicy, namespace string, isVerbose bool) {
	if isVerbose {
		framework.Logf("****************************************************************")
		framework.Logf("Network Policy creating %s/%s \n%s", namespace, policy.Name, prettyPrint(policy))
		framework.Logf("****************************************************************")
	}

	_, err := k8s.CreateOrUpdateNetworkPolicy(namespace, policy)
	framework.ExpectNoError(err, "Unable to create/update netpol %s/%s", namespace, policy.Name)
}

// ValidateOrFail validates connectivity
func ValidateOrFail(k8s *Kubernetes, model *Model, testCase *TestCase, isVerbose bool) {
	ginkgo.By("Validating reachability matrix...")

	ProbePodToPodConnectivity(k8s, model, testCase)
	if _, wrong, _ := testCase.Reachability.Summary(); wrong != 0 {
		testCase.Reachability.PrintSummary(true, true, true)
		framework.Failf("Had %d wrong results in reachability matrix", wrong)
	} else {
		if isVerbose {
			testCase.Reachability.PrintSummary(true, true, true)
		}
		framework.Logf("VALIDATION SUCCESSFUL")
	}
}

// UpdateNamespaceLabels sets the labels for a namespace
func UpdateNamespaceLabels(k8s *Kubernetes, ns string, newNsLabel map[string]string) {
	err := k8s.setNamespaceLabels(ns, newNsLabel)
	framework.ExpectNoError(err, "Update namespace %s labels", ns)
	err = wait.PollImmediate(1*time.Second, 30*time.Second, func() (done bool, err error) {
		namespace, err := k8s.getNamespace(ns)
		if err != nil {
			return false, err
		}
		for key, expected := range newNsLabel {
			if actual, ok := namespace.Labels[key]; !ok || (expected != actual) {
				return false, nil
			}
		}
		return true, nil
	})
	framework.ExpectNoError(err, "Unable to wait for ns %s to update labels", ns)
}

// AddPodLabels adds new labels to a deployment's template
func AddPodLabels(k8s *Kubernetes, pod *Pod, newPodLabels map[string]string) {
	kubePod, err := k8s.ClientSet.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get pod %s/%s", pod.Namespace, pod.Name)
	for key, val := range newPodLabels {
		kubePod.Labels[key] = val
	}
	_, err = k8s.ClientSet.CoreV1().Pods(pod.Namespace).Update(context.TODO(), kubePod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to add pod %s/%s labels", pod.Namespace, pod.Name)

	err = wait.PollImmediate(1*time.Second, 30*time.Second, func() (done bool, err error) {
		waitForPod, err := k8s.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return false, err
		}
		for key, expected := range newPodLabels {
			if actual, ok := waitForPod.Labels[key]; !ok || (expected != actual) {
				return false, nil
			}
		}
		return true, nil
	})
	framework.ExpectNoError(err, "Unable to wait for pod %s/%s to update labels", pod.Namespace, pod.Name)
}

// ResetNamespaceLabels resets the labels for a namespace
func ResetNamespaceLabels(k8s *Kubernetes, ns string) {
	UpdateNamespaceLabels(k8s, ns, (&Namespace{Name: ns}).LabelSelector())
}

// ResetPodLabels resets the labels for a deployment's template
func ResetPodLabels(k8s *Kubernetes, pod *Pod) {
	kubePod, err := k8s.ClientSet.CoreV1().Pods(pod.Namespace).Get(context.TODO(), pod.Name, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get pod %s/%s", pod.Namespace, pod.Name)
	kubePod.Labels = pod.LabelSelector()
	_, err = k8s.ClientSet.CoreV1().Pods(pod.Namespace).Update(context.TODO(), kubePod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to add pod %s/%s labels", pod.Namespace, pod.Name)

	err = wait.PollImmediate(1*time.Second, 30*time.Second, func() (done bool, err error) {
		waitForPod, err := k8s.GetPod(pod.Namespace, pod.Name)
		if err != nil {
			return false, err
		}
		for key, expected := range pod.LabelSelector() {
			if actual, ok := waitForPod.Labels[key]; !ok || (expected != actual) {
				return false, nil
			}
		}
		return true, nil
	})
	framework.ExpectNoError(err, "Unable to wait for pod %s/%s to update labels", pod.Namespace, pod.Name)
}
