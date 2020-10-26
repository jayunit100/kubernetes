/*
Copyright 2016 The Kubernetes Authors.

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
	"k8s.io/apimachinery/pkg/util/wait"
	"time"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/kubernetes/test/e2e/network"
	utilnet "k8s.io/utils/net"

	"github.com/onsi/ginkgo"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
)

const (
	addSCTPContainers  = false
	isVerbose          = true
	useFixedNamespaces = false
)

/*
You might be wondering, why are there multiple namespaces used for each test case?

These tests are based on "truth tables" that compare the expected and actual connectivity of each pair of pods.
Since network policies live in namespaces, and peers can be selected by namespace,
howing the connectivity of pods in other namespaces is key information to show whether a network policy is working as intended or not.

We use 3 namespaces each with 3 pods, and probe all combinations ( 9 pods x 9 pods = 81 data points ) -- including cross-namespace calls.

Here's an example of a test run, showing the expected and actual connectivity, along with the differences.  Note how the
visual representation as a truth table greatly aids in understanding what a network policy is intended to do in theory
and what is happening in practice:

		Oct 19 10:34:16.907: INFO: expected:

		-	x/a	x/b	x/c	y/a	y/b	y/c	z/a	z/b	z/c
		x/a	X	.	.	.	.	.	.	.	.
		x/b	X	.	.	.	.	.	.	.	.
		x/c	X	.	.	.	.	.	.	.	.
		y/a	.	.	.	.	.	.	.	.	.
		y/b	.	.	.	.	.	.	.	.	.
		y/c	.	.	.	.	.	.	.	.	.
		z/a	X	.	.	.	.	.	.	.	.
		z/b	X	.	.	.	.	.	.	.	.
		z/c	X	.	.	.	.	.	.	.	.

		Oct 19 10:34:16.907: INFO: observed:

		-	x/a	x/b	x/c	y/a	y/b	y/c	z/a	z/b	z/c
		x/a	X	.	.	.	.	.	.	.	.
		x/b	X	.	.	.	.	.	.	.	.
		x/c	X	.	.	.	.	.	.	.	.
		y/a	.	.	.	.	.	.	.	.	.
		y/b	.	.	.	.	.	.	.	.	.
		y/c	.	.	.	.	.	.	.	.	.
		z/a	X	.	.	.	.	.	.	.	.
		z/b	X	.	.	.	.	.	.	.	.
		z/c	X	.	.	.	.	.	.	.	.

		Oct 19 10:34:16.907: INFO: comparison:

		-	x/a	x/b	x/c	y/a	y/b	y/c	z/a	z/b	z/c
		x/a	.	.	.	.	.	.	.	.	.
		x/b	.	.	.	.	.	.	.	.	.
		x/c	.	.	.	.	.	.	.	.	.
		y/a	.	.	.	.	.	.	.	.	.
		y/b	.	.	.	.	.	.	.	.	.
		y/c	.	.	.	.	.	.	.	.	.
		z/a	.	.	.	.	.	.	.	.	.
		z/b	.	.	.	.	.	.	.	.	.
		z/c	.	.	.	.	.	.	.	.	.
*/
var _ = network.SIGDescribe("Netpol [LinuxOnly]", func() {
	f := framework.NewDefaultFramework("netpol")

	shouldCreateRandomPolicies := true
	ginkgo.BeforeEach(func() {
		if shouldCreateRandomPolicies {
			if useFixedNamespaces {
				initializeResources(f)
			}
			for _, policy := range GetRandomIngressPolicies(21) {
				_, err := f.ClientSet.NetworkingV1().NetworkPolicies("default").Create(context.TODO(), policy, metav1.CreateOptions{})
				if err != nil {
					framework.Logf("unable to create netpol default/%s: %+v", policy.Name, err)
				}
			}
			shouldCreateRandomPolicies = false
		}
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.BeforeEach(func() {
			if useFixedNamespaces {
				_, _, _, model, k8s := getK8SModel(f)
				framework.ExpectNoError(k8s.CleanNetworkPolicies(model.NamespaceNames), "unable to clean network policies")
				err := wait.Poll(1*time.Second, 30*time.Second, func() (done bool, err error) {
					for _, ns := range model.NamespaceNames {
						netpols, err := k8s.ClientSet.NetworkingV1().NetworkPolicies(ns).List(context.TODO(), metav1.ListOptions{})
						framework.ExpectNoError(err, "get network policies from ns %s", ns)
						if len(netpols.Items) > 0 {
							return false, nil
						}
					}
					return true, nil
				})
				framework.ExpectNoError(err, "unable to wait for network policy deletion")
			} else {
				framework.ExpectNoError(initializeResources(f), "unable to initialize resources")
			}
		})

		ginkgo.AfterEach(func() {
			if !useFixedNamespaces {
				_, _, _, model, k8s := getK8SModel(f)
				framework.ExpectNoError(k8s.deleteNamespaces(model.NamespaceNames), "unable to clean up netpol namespaces")
			}
		})

		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:Netpol]", func() {
			nsX, _, _, model, k8s := getK8SModel(f)
			policy := GetDenyIngress("deny-ingress")
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: nsX}, false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:Netpol]", func() {
			np := &networkingv1.NetworkPolicy{}
			policy := `
			{
				"kind": "NetworkPolicy",
				"apiVersion": "networking.k8s.io/v1",
				"metadata": {
				   "name": "deny-all-tcp-allow-dns"
				},
				"spec": {
				   "podSelector": {
					  "matchLabels": {}
				   },
				   "ingress": [],
				   "egress": [{
						"ports": [
							{
								"protocol": "UDP",
								"port": 53
							}
						]
					}],
				   "policyTypes": [
					"Ingress",
					"Egress"
				   ]
				}
			 }
			 `
			err := json.Unmarshal([]byte(policy), np)
			framework.ExpectNoError(err, "unmarshal network policy")

			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, np, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: nsX}, false)
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{}, false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:Netpol]", func() {
			allowedPods := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsX, "b"), NewPodString(nsX, "a"), true)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:Netpol]", func() {
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": nsY,
				},
			}
			policy := GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{Namespace: nsX, Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: nsZ}, &Peer{Namespace: nsX, Pod: "a"}, false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy based on PodSelector with MatchExpressions[Feature:Netpol]", func() {
			allowedPods := metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy := GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsX, "b"), NewPodString(nsX, "a"), true)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:Netpol]", func() {
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{nsY},
				}},
			}
			policy := GetAllowIngressByNamespace("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{Namespace: nsX, Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: nsZ}, &Peer{Namespace: nsX, Pod: "a"}, false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:Netpol]", func() {
			nsX, _, _, model, k8s := getK8SModel(f)
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{nsX},
				}},
			}
			podBAllowlisting := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := GetAllowIngressByNamespaceOrPod("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces, podBAllowlisting)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.Expect(NewPodString(nsX, "a"), NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsX, "c"), NewPodString(nsX, "a"), false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:Netpol]", func() {
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{nsX},
				}},
			}
			allowedPod := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := GetAllowIngressByNamespaceAndPod("allow-ns-y-podselector-and-nsselector", map[string]string{"pod": "a"}, allowedNamespaces, allowedPod)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsY, "b"), NewPodString(nsX, "a"), true)
			reachability.Expect(NewPodString(nsZ, "b"), NewPodString(nsX, "a"), true)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy based on Multiple PodSelectors and NamespaceSelectors [Feature:Netpol]", func() {
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{nsX},
				}},
			}
			allowedPod := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b", "c"},
				}},
			}
			policy := GetAllowIngressByNamespaceAndPod("allow-ns-y-z-pod-b-c", map[string]string{"pod": "a"}, allowedNamespaces, allowedPod)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{Namespace: nsX, Pod: "a"}, false)
			reachability.Expect(NewPodString(nsY, "a"), NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsZ, "a"), NewPodString(nsX, "a"), false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:Netpol]", func() {
			nsX, nsY, _, model, k8s := getK8SModel(f)
			allowedNamespaces := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": nsY,
				},
			}
			allowedPods := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "a",
				},
			}
			policy := GetAllowIngressByNamespaceAndPod("allow-ns-y-pod-a-via-namespace-pod-selector", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsY, "a"), NewPodString(nsX, "a"), true)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:Netpol]", func() {
			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": nsY,
				},
			}
			allowPort81Policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})
			CreateOrUpdatePolicy(k8s, allowPort81Policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{Namespace: nsX, Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: nsY}, &Peer{Namespace: nsX, Pod: "a"}, true)
			reachability.ExpectPeer(&Peer{Namespace: nsZ}, &Peer{Namespace: nsX, Pod: "a"}, false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce multiple, stacked policies with overlapping podSelectors [Feature:Netpol]", func() {
			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": nsY,
				},
			}
			allowPort81Policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})
			CreateOrUpdatePolicy(k8s, allowPort81Policy, nsX, true)

			reachabilityALLOW := NewReachability(model.AllPods(), true)
			reachabilityALLOW.ExpectPeer(&Peer{Namespace: nsX}, &Peer{Namespace: nsX, Pod: "a"}, false)
			reachabilityALLOW.ExpectPeer(&Peer{Namespace: nsY}, &Peer{Namespace: nsX, Pod: "a"}, true)
			reachabilityALLOW.ExpectPeer(&Peer{Namespace: nsZ}, &Peer{Namespace: nsX, Pod: "a"}, false)

			ginkgo.By("Verifying traffic on port 81.")
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityALLOW}, isVerbose)

			reachabilityDENY := NewReachability(model.AllPods(), true)
			reachabilityDENY.ExpectAllIngress(NewPodString(nsX, "a"), false)

			ginkgo.By("Verifying traffic on port 80.")
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityDENY}, isVerbose)

			allowPort80Policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 80})
			CreateOrUpdatePolicy(k8s, allowPort80Policy, nsX, true)

			ginkgo.By("Verifying that we can add a policy to unblock port 80")
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityALLOW}, isVerbose)
		})

		ginkgo.It("should support allow-all policy [Feature:Netpol]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			policy := GetAllowIngress("allow-all")
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:Netpol]", func() {
			policy := GetAllowIngressByPort("allow-all", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81-tcp"})
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			ginkgo.By("Blocking all ports other then 81 in the entire namespace")

			reachabilityPort81 := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityPort81}, isVerbose)

			// disallow all traffic to the x namespace
			reachabilityPort80 := NewReachability(model.AllPods(), true)
			reachabilityPort80.ExpectPeer(&Peer{}, &Peer{Namespace: nsX}, false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityPort80}, isVerbose)
		})

		ginkgo.It("should allow ingress access from namespace on one named port [Feature:Netpol]", func() {
			nsX, nsY, nsZ, model, k8s := getK8SModel(f)
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": nsY,
				},
			}
			policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{Namespace: nsX, Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: nsZ}, &Peer{Namespace: nsX, Pod: "a"}, false)

			ginkgo.By("Verify that port 80 is allowed for namespace y")
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			ginkgo.By("Verify that port 81 is blocked for all namespaces including y")
			reachabilityFAIL := NewReachability(model.AllPods(), true)
			reachabilityFAIL.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityFAIL}, isVerbose)
		})

		ginkgo.It("should allow egress access on one named port [Feature:Netpol]", func() {
			ginkgo.By("validating egress from port 81 to port 80")
			policy := GetAllowEgressByPort("allow-egress", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachabilityPort80 := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityPort80}, isVerbose)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachabilityPort81 := NewReachability(model.AllPods(), true)
			reachabilityPort81.ExpectPeer(&Peer{Namespace: nsX}, &Peer{}, false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityPort81}, isVerbose)
		})

		ginkgo.It("should enforce updated policy [Feature:Netpol]", func() {
			ginkgo.By("Using the simplest possible mutation: start with allow all, then switch to deny all")
			// part 1) allow all
			policy := GetAllowIngress("allow-all-mutate-to-deny-all")
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			// part 2) update the policy to deny all
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachabilityDeny := NewReachability(model.AllPods(), true)
			reachabilityDeny.ExpectPeer(&Peer{}, &Peer{Namespace: nsX}, false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityDeny}, isVerbose)
		})

		ginkgo.It("should allow ingress access from updated namespace [Feature:Netpol]", func() {
			nsX, nsY, _, model, k8s := getK8SModel(f)
			defer ResetNamespaceLabels(k8s, nsY)

			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns2": "updated",
				},
			}
			policy := GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			// add a new label, we'll remove it after this test is completed
			updatedLabels := map[string]string{
				"ns":  nsY,
				"ns2": "updated",
			}
			UpdateNamespaceLabels(k8s, nsY, updatedLabels)

			// anything from namespace 'y' should be able to get to x/a
			reachabilityWithLabel := NewReachability(model.AllPods(), true)
			reachabilityWithLabel.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachabilityWithLabel.ExpectPeer(&Peer{Namespace: nsY}, &Peer{}, true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityWithLabel}, isVerbose)
		})

		ginkgo.It("should allow ingress access from updated pod [Feature:Netpol]", func() {
			nsX, _, _, model, k8s := getK8SModel(f)
			podXB, err := model.FindPod(nsX, "b")
			framework.ExpectNoError(err, "find pod x/b")
			defer ResetPodLabels(k8s, podXB)

			// add a new label, we'll remove it after this test is done
			matchLabels := map[string]string{"pod": "b", "pod2": "updated"}
			allowedLabels := &metav1.LabelSelector{MatchLabels: matchLabels}
			policy := GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedLabels)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			// now update label in x namespace and pod b
			AddPodLabels(k8s, podXB, matchLabels)

			ginkgo.By("x/b is able to reach x/a when label is updated")

			reachabilityWithLabel := NewReachability(model.AllPods(), true)
			reachabilityWithLabel.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachabilityWithLabel.Expect(NewPodString(nsX, "b"), NewPodString(nsX, "a"), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityWithLabel}, isVerbose)
		})

		ginkgo.It("should deny ingress access to updated pod [Feature:Netpol]", func() {
			nsX, _, _, model, k8s := getK8SModel(f)
			podXA, err := model.FindPod(nsX, "a")
			framework.ExpectNoError(err, "find pod x/a")
			defer ResetPodLabels(k8s, podXA)

			policy := GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: map[string]string{"target": "isolated"}})
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			ginkgo.By("Verify that everything can reach x/a")
			reachability := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			AddPodLabels(k8s, podXA, map[string]string{"target": "isolated"})

			reachabilityIsolated := NewReachability(model.AllPods(), true)
			reachabilityIsolated.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityIsolated}, isVerbose)
		})

		ginkgo.It("should work with Ingress, Egress specified together [Feature:Netpol]", func() {
			allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
			policy := GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)
			// add an egress rule on to it...
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"},
						},
						{
							Protocol: &protocolUDP,
							Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
						},
					},
				},
			}
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachabilityPort80 := NewReachability(model.AllPods(), true)
			reachabilityPort80.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachabilityPort80.Expect(NewPodString(nsX, "b"), NewPodString(nsX, "a"), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityPort80}, isVerbose)

			ginkgo.By("validating that port 81 doesn't work")
			// meanwhile no egress traffic on 81 should work, since our egress policy is on 80
			reachabilityPort81 := NewReachability(model.AllPods(), true)
			reachabilityPort81.ExpectAllIngress(NewPodString(nsX, "a"), false)
			reachabilityPort81.ExpectAllEgress(NewPodString(nsX, "a"), false)
			reachabilityPort81.Expect(NewPodString(nsX, "b"), NewPodString(nsX, "a"), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityPort81}, isVerbose)
		})

		ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:Netpol]", func() {
			nsX, nsY, _, model, k8s := getK8SModel(f)
			allowedNamespaces := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": nsY,
				},
			}
			allowedPods := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "a",
				},
			}
			policy := GetAllowEgressByNamespaceAndPod("allow-to-ns-y-pod-a", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllEgress(NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsX, "a"), NewPodString(nsY, "a"), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:Netpol]", func() {
			nsX, _, _, model, k8s := getK8SModel(f)
			policyAllowOnlyPort80 := GetAllowIngressByPort("allow-ingress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			CreateOrUpdatePolicy(k8s, policyAllowOnlyPort80, nsX, true)

			ginkgo.By("The policy targets port 80 -- so let's make sure traffic on port 81 is blocked")

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: nsX}, false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			ginkgo.By("Allowing all ports")

			policyAllowAll := GetAllowIngress("allow-ingress")
			CreateOrUpdatePolicy(k8s, policyAllowAll, nsX, true)

			reachabilityAll := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityAll}, isVerbose)
		})

		ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:Netpol]", func() {
			policyAllowPort80 := GetAllowEgressByPort("allow-egress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policyAllowPort80, nsX, true)

			ginkgo.By("Making sure ingress doesn't work other than port 80")

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{}, false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			ginkgo.By("Allowing all ports")

			policyAllowAll := GetAllowEgress()
			CreateOrUpdatePolicy(k8s, policyAllowAll, nsX, true)

			reachabilityAll := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachabilityAll}, isVerbose)
		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:Netpol]", func() {
			ginkgo.By("Creating a network policy for the server which denies all traffic.")

			// Deny all traffic into and out of "x".
			policy := GetDenyAll("deny-all")
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)
			reachability := NewReachability(model.AllPods(), true)

			// Expect all traffic into, and out of "x" to be False.
			reachability.ExpectPeer(&Peer{Namespace: nsX}, &Peer{}, false)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: nsX}, false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			err := k8s.CleanNetworkPolicies(model.NamespaceNames)
			time.Sleep(3 * time.Second) // TODO we can remove this eventually, its just a hack to keep CI stable.
			framework.ExpectNoError(err, "unable to clean network policies")

			// Now the policiy is deleted, we expect all connectivity to work again.
			reachabilityAll := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityAll}, isVerbose)
		})

		ginkgo.It("should allow egress access to server in CIDR block [Feature:Netpol]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR
			nsX, nsY, _, model, k8s := getK8SModel(f)
			podList, err := f.ClientSet.CoreV1().Pods(nsY).List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to list pods in namespace y")
			pod := podList.Items[0]

			hostMask := 32
			if utilnet.IsIPv6String(pod.Status.PodIP) {
				hostMask = 128
			}
			podServerCIDR := fmt.Sprintf("%s/%d", pod.Status.PodIP, hostMask)
			policyAllowCIDR := GetAllowEgressByCIDR("a", podServerCIDR)
			CreateOrUpdatePolicy(k8s, policyAllowCIDR, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllEgress(NewPodString(nsX, "a"), false)
			reachability.Expect(NewPodString(nsX, "a"), NewPodString(nsY, "b"), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should enforce except clause while egress access to server in CIDR block [Feature:Netpol]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			nsX, _, _, model, k8s := getK8SModel(f)
			podList, err := f.ClientSet.CoreV1().Pods(nsX).List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to find pod x/a")
			podA := podList.Items[0]

			podServerAllowCIDR := fmt.Sprintf("%s/4", podA.Status.PodIP)

			podList, err = f.ClientSet.CoreV1().Pods(nsX).List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to find pod x/b")
			podB := podList.Items[0]

			podServerExceptList := []string{fmt.Sprintf("%s/32", podB.Status.PodIP)}
			policyAllowCIDR := GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)
			CreateOrUpdatePolicy(k8s, policyAllowCIDR, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.Expect(NewPodString(nsX, "a"), NewPodString(nsX, "b"), false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed [Feature:Netpol]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			nsX, _, _, model, k8s := getK8SModel(f)
			podList, err := f.ClientSet.CoreV1().Pods(nsX).List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to find pod x/a")
			podA := podList.Items[0]

			podList, err = f.ClientSet.CoreV1().Pods(nsX).List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to find pod x/b")
			podB := podList.Items[0]

			// Exclude podServer's IP with an Except clause
			podServerAllowCIDR := fmt.Sprintf("%s/4", podA.Status.PodIP)
			podServerExceptList := []string{fmt.Sprintf("%s/32", podB.Status.PodIP)}
			policyAllowCIDR := GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)
			CreateOrUpdatePolicy(k8s, policyAllowCIDR, nsX, true)

			reachability := NewReachability(model.AllPods(), true)
			reachability.Expect(NewPodString(nsX, "a"), NewPodString(nsX, "b"), false)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)

			podBIP := fmt.Sprintf("%s/32", podB.Status.PodIP)
			//// Create NetworkPolicy which allows access to the podServer using podServer's IP in allow CIDR.
			allowPolicy := GetAllowEgressByCIDR("a", podBIP)
			CreateOrUpdatePolicy(k8s, allowPolicy, nsX, true)

			reachabilityAllow := NewReachability(model.AllPods(), true)
			reachabilityAllow.ExpectAllEgress(NewPodString(nsX, "a"), false)
			reachabilityAllow.Expect(NewPodString(nsX, "a"), NewPodString(nsX, "b"), true)

			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: reachabilityAllow}, isVerbose)
		})

		ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:Netpol]", func() {
			/*
					Test steps:
					1. Verify every pod in every namespace can talk to each other
				       - including a -> b and b -> a
					2. Create a policy to allow egress a -> b (target = a)
				    3. Create a policy to *deny* ingress b -> a (target = a)
					4. Verify a -> b allowed; b -> a blocked
			*/
			targetLabels := map[string]string{"pod": "a"}

			ginkgo.By("Creating a network policy for pod-a which allows Egress traffic to pod-b.")

			allowEgressPolicy := GetAllowEgressForTarget(metav1.LabelSelector{MatchLabels: targetLabels})
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, allowEgressPolicy, nsX, true)

			allowEgressReachability := NewReachability(model.AllPods(), true)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: allowEgressReachability}, isVerbose)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")

			denyAllIngressPolicy := GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: targetLabels})
			CreateOrUpdatePolicy(k8s, denyAllIngressPolicy, nsX, true)

			denyIngressToXReachability := NewReachability(model.AllPods(), true)
			denyIngressToXReachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 80, Protocol: v1.ProtocolTCP, Reachability: denyIngressToXReachability}, isVerbose)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only SCTP [Feature:Netpol] [Feature:SCTP]", func() {
			policy := GetAllowIngressOnProtocolByPort("allow-only-sctp-ingress-on-port-81", v1.ProtocolSCTP, map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			ginkgo.By("Creating a network policy for the server which allows traffic only via SCTP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only UDP [Feature:Netpol] [Feature:UDP]", func() {
			policy := GetAllowIngressOnProtocolByPort("allow-only-udp-ingress-on-port-81", v1.ProtocolUDP, map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			nsX, _, _, model, k8s := getK8SModel(f)
			CreateOrUpdatePolicy(k8s, policy, nsX, true)

			ginkgo.By("Creating a network policy for the server which allows traffic only via UDP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := NewReachability(model.AllPods(), true)
			reachability.ExpectAllIngress(NewPodString(nsX, "a"), false)
			ValidateOrFail(k8s, model, &TestCase{FromPort: 81, ToPort: 81, Protocol: v1.ProtocolTCP, Reachability: reachability}, isVerbose)
		})

	})
})

func getNamespaces(rootNs string) (string, string, string, []string) {
	if useFixedNamespaces {
		rootNs = ""
	} else {
		rootNs = rootNs + "-"
	}
	nsX := fmt.Sprintf("%sx", rootNs)
	nsY := fmt.Sprintf("%sy", rootNs)
	nsZ := fmt.Sprintf("%sz", rootNs)
	return nsX, nsY, nsZ, []string{nsX, nsY, nsZ}
}

func defaultModel(namespaces []string) *Model {
	protocols := []v1.Protocol{v1.ProtocolTCP, v1.ProtocolUDP}
	if addSCTPContainers {
		protocols = append(protocols, v1.ProtocolSCTP)
	}
	return NewModel(namespaces, []string{"a", "b", "c"}, []int32{80, 81}, protocols)
}

func getK8SModel(f *framework.Framework) (string, string, string, *Model, *Kubernetes) {
	k8s := NewKubernetes(f.ClientSet)
	rootNs := f.Namespace.GetName()
	nsX, nsY, nsZ, namespaces := getNamespaces(rootNs)

	model := defaultModel(namespaces)

	return nsX, nsY, nsZ, model, k8s
}

func initializeResources(f *framework.Framework) error {
	_, _, _, model, k8s := getK8SModel(f)

	framework.Logf("initializing cluster: ensuring namespaces, deployments, and pods exist and are ready")

	err := k8s.InitializeCluster(model)
	if err != nil {
		return err
	}

	framework.Logf("finished initializing cluster state")

	return k8s.waitForHTTPServers(model)
}
