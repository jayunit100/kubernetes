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
	k8syaml "sigs.k8s.io/yaml"

	"gopkg.in/yaml.v2"
	"time"

	"github.com/onsi/ginkgo"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"
)

// prettyPrint a networkPolicy
func jsonPrettyPrint(policy *networkingv1.NetworkPolicy) string {
	raw, _ := json.MarshalIndent(policy, "", "\t")
	return string(raw)
}

// prettyPrint a networkPolicy
func yamlPrettyPrint(policy *networkingv1.NetworkPolicy) string {
	raw, _ := yaml.Marshal(policy)
	return string(raw)
}

// prettyPrint a networkPolicy
func k8sYamlPrettyPrint(policy *networkingv1.NetworkPolicy) string {
	raw, _ := k8syaml.Marshal(policy)
	return string(raw)
}

// CreateOrUpdatePolicy fails if it can not create or update the policy in the given namespace
func CreateOrUpdatePolicy(k8s *Kubernetes, policy *networkingv1.NetworkPolicy, namespace string, isVerbose bool) {
	if isVerbose {
		fmt.Println("****************************************************************")
		framework.Logf("Network Policy creating %s/%s %v", namespace, policy.Name, yamlPrettyPrint(policy))
		framework.Logf("Network Policy creating %s/%s \n%v", namespace, policy.Name, k8sYamlPrettyPrint(policy))
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
		fmt.Println("VALIDATION SUCCESSFUL")
	}
}

// ResetNamespaceLabels returns a namespace's labels to their original state
func ResetNamespaceLabels(k8s *Kubernetes, ns string) {
	err := k8s.setNamespaceLabels(ns, map[string]string{"ns": ns})
	framework.ExpectNoError(err, "reset namespace %s labels", ns)
	time.Sleep(10 * time.Second)
}

// ResetDeploymentPodLabels returns a deployment's spec labels to their original state
func ResetDeploymentPodLabels(k8s *Kubernetes, pod *Pod) {
	deployment, err := k8s.ClientSet.AppsV1().Deployments(pod.Namespace).Get(context.TODO(), pod.DeploymentName(), metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get deployment %s/%s", pod.Namespace, pod.Name)
	deployment.Spec.Template.ObjectMeta.Labels = pod.LabelSelector()
	_, err = k8s.ClientSet.AppsV1().Deployments(pod.Namespace).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update deployment %s/%s labels", pod.Namespace, pod.Name)
	time.Sleep(10 * time.Second)
}

// UpdateNamespaceLabels sets the labels for a namespace
func UpdateNamespaceLabels(k8s *Kubernetes, ns string, newNsLabel map[string]string) {
	err := k8s.setNamespaceLabels(ns, newNsLabel)
	framework.ExpectNoError(err, "Update namespace %s labels", ns)
	time.Sleep(10 * time.Second)
}

// AddDeploymentPodLabels adds new labels to a deployment's template
func AddDeploymentPodLabels(k8s *Kubernetes, pod *Pod, newPodLabels map[string]string) {
	deployment, err := k8s.ClientSet.AppsV1().Deployments(pod.Namespace).Get(context.TODO(), pod.DeploymentName(), metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get deployment %s/%s", pod.Namespace, pod.Name)
	for key, val := range newPodLabels {
		deployment.Spec.Template.ObjectMeta.Labels[key] = val
	}
	_, err = k8s.ClientSet.AppsV1().Deployments(pod.Namespace).Update(context.TODO(), deployment, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to add deployment %s/%s labels", pod.Namespace, pod.Name)
	time.Sleep(10 * time.Second)
}
