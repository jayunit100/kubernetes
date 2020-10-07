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
	"fmt"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/kubernetes/test/e2e/network"
	utilnet "k8s.io/utils/net"
	"time"

	"github.com/onsi/ginkgo"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
)

var _ = network.SIGDescribe("Netpol [LinuxOnly]", func() {
	f := framework.NewDefaultFramework("netpol")

	var k8s *Kubernetes
	ginkgo.BeforeEach(func() {
		// The code in here only runs once bc it checks if things are nil
		if k8s == nil {
			var err error
			framework.Logf("instantiating Kubernetes helper")
			k8s = NewKubernetes(f.ClientSet)

			framework.ExpectNoError(err, "Unable to instantiate Kubernetes helper")
			framework.Logf("bootstrapping cluster: ensuring namespaces, deployments, and pods exist and are ready")

			k8s.Bootstrap(NetpolTestNamespaces, NetpolTestPods, GetAllPods())
			framework.Logf("finished bootstrapping cluster")

			//TODO move to different location for unit test
			if PodString("x/a") != NewPodString("x", "a") {
				framework.Failf("Namespace, pod representation doesn't match PodString type")
			}

			p := GetRandomIngressPolicies(21)
			for i := 0; i < 20; i++ {
				_, err := f.ClientSet.NetworkingV1().NetworkPolicies("default").Create(context.TODO(), p[i], metav1.CreateOptions{})
				if err != nil {
					framework.Logf("unable to create netpol %+v: %+v", p[i], err)
				}
			}
		}
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			CleanPolicies(k8s, NetpolTestNamespaces)
			ValidateAllConnectivity(k8s, NewScenario(83, 80, v1.ProtocolTCP))
		})

		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			policy := GetDenyIngress("deny-ingress")
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			policy := GetDenyAll("deny-all")
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: "x"}, false)
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{}, false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedPods := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: "z"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on PodSelector with MatchExpressions[Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedPods := metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy := GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := GetAllowIngressByNamespace("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: "z"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}
			podBAllowlisting := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := GetAllowIngressByNamespaceOrPod("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces, podBAllowlisting)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.Expect("x/c", "x/a", false)

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}
			allowedPod := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := GetAllowIngressByNamespaceAndPod("allow-ns-y-podselector-and-nsselector", map[string]string{"pod": "a"}, allowedNamespaces, allowedPod)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("y/b", "x/a", true)
			reachability.Expect("z/b", "x/a", true)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on Multiple PodSelectors and NamespaceSelectors [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
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
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.Expect("y/a", "x/a", false)
			reachability.Expect("z/a", "x/a", false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 80, v1.ProtocolTCP)

			allowedNamespaces := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowedPods := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "a",
				},
			}
			policy := GetAllowIngressByNamespaceAndPod("allow-ns-y-pod-a-via-namespace-pod-selector", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("y/a", "x/a", true)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:Netpol]", func() {
			ns := "x"
			scenario := NewScenario(82, 81, v1.ProtocolTCP)

			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowPort81Policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})
			CreateOrUpdatePolicy(k8s, allowPort81Policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: "y"}, &Peer{Namespace: "x", Pod: "a"}, true)
			reachability.ExpectPeer(&Peer{Namespace: "z"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce multiple, stacked policies with overlapping podSelectors [Feature:Netpol]", func() {
			ns := "x"
			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowPort81Policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})
			CreateOrUpdatePolicy(k8s, allowPort81Policy, ns, true)

			reachabilityALLOW := NewReachability(GetAllPods(), true)
			reachabilityALLOW.ExpectPeer(&Peer{Namespace: "x"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachabilityALLOW.ExpectPeer(&Peer{Namespace: "y"}, &Peer{Namespace: "x", Pod: "a"}, true)
			reachabilityALLOW.ExpectPeer(&Peer{Namespace: "z"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachabilityALLOW.AllowLoopback()

			ginkgo.By("Verifying traffic on port 81.")
			ValidateOrFail(k8s, reachabilityALLOW, NewScenario(82, 81, v1.ProtocolTCP), true)

			reachabilityDENY := NewReachability(GetAllPods(), true)
			reachabilityDENY.ExpectAllIngress("x/a", false)
			reachabilityDENY.AllowLoopback()

			ginkgo.By("Verifying traffic on port 80.")
			ValidateOrFail(k8s, reachabilityDENY, NewScenario(82, 80, v1.ProtocolTCP), true)

			allowPort80Policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 80})
			CreateOrUpdatePolicy(k8s, allowPort80Policy, ns, true)

			ginkgo.By("Verifying that we can add a policy to unblock port 80")
			ValidateOrFail(k8s, reachabilityALLOW, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should support allow-all policy [Feature:Netpol]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			ns := "x"
			policy := GetAllowIngress("allow-all")
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)
			ValidateOrFail(k8s, reachability, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:Netpol]", func() {
			ns := "x"
			policy := GetAllowIngressByPort("allow-all", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81-tcp"})
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			// WARNING ! Since we are adding a port rule, that means that the lack of a
			// pod selector will cause this policy to target the ENTIRE namespace
			ginkgo.By("Blocking all ports other then 81 in the entire namespace")

			reachabilityPort81 := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachabilityPort81, NewScenario(82, 81, v1.ProtocolTCP), true)

			// disallow all traffic to the x namespace
			reachabilityPort80 := NewReachability(GetAllPods(), true)
			reachabilityPort80.ExpectPeer(&Peer{}, &Peer{Namespace: "x"}, false)
			reachabilityPort80.AllowLoopback()
			ValidateOrFail(k8s, reachabilityPort80, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access from namespace on one named port [Feature:Netpol]", func() {
			ns := "x"
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&Peer{Namespace: "z"}, &Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			ginkgo.By("Verify that port 80 is allowed for namespace y")
			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			ginkgo.By("Verify that port 81 is blocked for all namespaces including y")
			reachabilityFAIL := NewReachability(GetAllPods(), true)
			reachabilityFAIL.ExpectAllIngress("x/a", false)
			reachabilityFAIL.AllowLoopback()

			ValidateOrFail(k8s, reachabilityFAIL, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow egress access on one named port [Feature:Netpol]", func() {
			ginkgo.By("validating egress from port 82 to port 80")
			ns := "x"
			policy := GetAllowEgressByPort("allow-egress", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			CreateOrUpdatePolicy(k8s, policy, ns, true)
			// By adding a port rule to the egress class we now restrict egress to only work on port 80.
			// TODO What about DNS -- we removed that check.  Write a higher level DNS checking test
			//   which can be used to fulfill that requirement.

			reachabilityPort80 := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachabilityPort80, NewScenario(82, 80, v1.ProtocolTCP), true)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachabilityPort81 := NewReachability(GetAllPods(), true)
			reachabilityPort81.ExpectPeer(&Peer{Namespace: "x"}, &Peer{}, false)
			reachabilityPort81.AllowLoopback()

			ValidateOrFail(k8s, reachabilityPort81, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce updated policy [Feature:Netpol]", func() {
			ginkgo.By("Using the simplest possible mutation: start with allow all, then switch to deny all")
			// part 1) allow all
			ns := "x"
			policy := GetAllowIngress("allow-all-mutate-to-deny-all")
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachability, NewScenario(82, 81, v1.ProtocolTCP), true)

			// part 2) update the policy to deny all
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachabilityDeny := NewReachability(GetAllPods(), true)
			reachabilityDeny.ExpectPeer(&Peer{}, &Peer{Namespace: "x"}, false)
			reachabilityDeny.AllowLoopback()

			ValidateOrFail(k8s, reachabilityDeny, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access from updated namespace [Feature:Netpol]", func() {
			ResetNamespaceLabels(f, "y")
			defer ResetNamespaceLabels(f, "y")

			ns := "x"
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns2": "updated",
				},
			}
			policy := GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			// add a new label, we'll remove it after this test is completed
			updatedLabels := map[string]string{
				"ns":  "y",
				"ns2": "updated",
			}
			UpdateNamespaceLabels(f, "y", updatedLabels)

			// anything from namespace 'y' should be able to get to x/a
			reachability.ExpectPeer(&Peer{Namespace: "y"}, &Peer{}, true)

			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access from updated pod [Feature:Netpol]", func() {
			ResetDeploymentPodLabels(f, "x", "b")
			defer ResetDeploymentPodLabels(f, "x", "b")

			// add a new label, we'll remove it after this test is done
			ns := "x"
			matchLabels := map[string]string{"pod": "b", "pod2": "updated"}
			allowedLabels := &metav1.LabelSelector{MatchLabels: matchLabels}
			policy := GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedLabels)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			// now update label in x namespace and pod b
			AddDeploymentPodLabels(f, "x", "b", matchLabels)

			ginkgo.By("There is connection between x/b to x/a when label is updated")
			reachability.Expect("x/b", "x/a", true)
			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should deny ingress access to updated pod [Feature:Netpol]", func() {
			ResetDeploymentPodLabels(f, "x", "a")
			defer ResetDeploymentPodLabels(f, "x", "a")

			ns := "x"
			policy := GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: map[string]string{"target": "isolated"}})
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Verify that everything can reach x/a")
			reachability := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			AddDeploymentPodLabels(f, "x", "a", map[string]string{"target": "isolated"})
			reachabilityIsolated := NewReachability(GetAllPods(), true)
			reachabilityIsolated.ExpectAllIngress("x/a", false)
			reachabilityIsolated.AllowLoopback()
			ValidateOrFail(k8s, reachabilityIsolated, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should work with Ingress, Egress specified together [Feature:Netpol]", func() {
			ns := "x"
			allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
			policy := GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)
			// add an egress rule on to it...
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"},
						},
					},
				},
			}
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachabilityPort80 := NewReachability(GetAllPods(), true)
			reachabilityPort80.ExpectAllIngress("x/a", false)
			reachabilityPort80.Expect("x/b", "x/a", true)
			reachabilityPort80.AllowLoopback()
			ValidateOrFail(k8s, reachabilityPort80, NewScenario(82, 80, v1.ProtocolTCP), true)

			ginkgo.By("validating that port 81 doesn't work")
			// meanwhile no egress traffic on 81 should work, since our egress policy is on 80
			reachabilityPort81 := NewReachability(GetAllPods(), true)
			reachabilityPort81.ExpectAllIngress("x/a", false)
			reachabilityPort81.ExpectAllEgress("x/a", false)
			reachabilityPort81.Expect("x/b", "x/a", true)
			reachabilityPort81.AllowLoopback()
			ValidateOrFail(k8s, reachabilityPort81, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:Netpol]", func() {
			ns := "x"
			allowedNamespaces := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowedPods := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "a",
				},
			}
			policy := GetAllowEgressByNamespaceAndPod("allow-to-ns-y-pod-a", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.Expect("x/a", "y/a", true)
			reachability.AllowLoopback()

			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:Netpol]", func() {
			ns := "x"
			policyAllowOnlyPort80 := GetAllowIngressByPort("allow-ingress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			CreateOrUpdatePolicy(k8s, policyAllowOnlyPort80, ns, true)

			ginkgo.By("The policy targets port 80 -- so let's make sure traffic on port 81 is blocked")

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()
			ValidateOrFail(k8s, reachability, NewScenario(82, 81, v1.ProtocolTCP), true)

			ginkgo.By("Allowing all ports")

			policyAllowAll := GetAllowIngress("allow-ingress")
			CreateOrUpdatePolicy(k8s, policyAllowAll, ns, true)

			reachabilityAll := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachabilityAll, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:Netpol]", func() {
			ns := "x"
			policyAllowPort80 := GetAllowEgressByPort("allow-egress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			CreateOrUpdatePolicy(k8s, policyAllowPort80, ns, true)

			ginkgo.By("Making sure ingress doesn't work other than port 80")

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{}, false)
			reachability.AllowLoopback()
			ValidateOrFail(k8s, reachability, NewScenario(82, 81, v1.ProtocolTCP), true)

			ginkgo.By("Allowing all ports")

			policyAllowAll := GetAllowEgress()
			CreateOrUpdatePolicy(k8s, policyAllowAll, ns, true)

			reachabilityAll := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachabilityAll, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:Netpol]", func() {
			ginkgo.By("Creating a network policy for the server which denies all traffic.")
			ns := "x"
			policy := GetDenyAll("deny-all")
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectPeer(&Peer{Namespace: "x"}, &Peer{}, false)
			reachability.ExpectPeer(&Peer{}, &Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()
			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			err := k8s.CleanNetworkPolicies(NetpolTestNamespaces)
			time.Sleep(3 * time.Second)
			framework.ExpectNoError(err, "unable to clean network policies")

			reachabilityAll := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, reachabilityAll, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow egress access to server in CIDR block [Feature:Netpol]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR
			podList, err := f.ClientSet.CoreV1().Pods("y").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to list pods in namespace y")
			pod := podList.Items[0]

			hostMask := 32
			if utilnet.IsIPv6String(pod.Status.PodIP) {
				hostMask = 128
			}
			podServerCIDR := fmt.Sprintf("%s/%d", pod.Status.PodIP, hostMask)
			policyAllowCIDR := GetAllowEgressByCIDR("a", podServerCIDR)
			ns := "x"
			CreateOrUpdatePolicy(k8s, policyAllowCIDR, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.Expect("x/a", "y/b", true)
			reachability.AllowLoopback()
			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce except clause while egress access to server in CIDR block [Feature:Netpol]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to find pod x/a")
			podA := podList.Items[0]

			podServerAllowCIDR := fmt.Sprintf("%s/4", podA.Status.PodIP)

			podList, err = f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to find pod x/b")
			podB := podList.Items[0]

			podServerExceptList := []string{fmt.Sprintf("%s/32", podB.Status.PodIP)}
			ns := "x"
			policyAllowCIDR := GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)
			CreateOrUpdatePolicy(k8s, policyAllowCIDR, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.Expect("x/a", "x/b", false)

			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed [Feature:Netpol]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to find pod x/a")
			podA := podList.Items[0]

			podList, err = f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to find pod x/b")
			podB := podList.Items[0]

			// Exclude podServer's IP with an Except clause
			podServerAllowCIDR := fmt.Sprintf("%s/4", podA.Status.PodIP)
			podServerExceptList := []string{fmt.Sprintf("%s/32", podB.Status.PodIP)}
			ns := "x"
			policyAllowCIDR := GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)
			CreateOrUpdatePolicy(k8s, policyAllowCIDR, ns, true)

			reachability := NewReachability(GetAllPods(), true)
			reachability.Expect("x/a", "x/b", false)

			ValidateOrFail(k8s, reachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			podBIP := fmt.Sprintf("%s/32", podB.Status.PodIP)
			//// Create NetworkPolicy which allows access to the podServer using podServer's IP in allow CIDR.
			allowPolicy := GetAllowEgressByCIDR("a", podBIP)
			CreateOrUpdatePolicy(k8s, allowPolicy, ns, true)

			reachabilityAllow := NewReachability(GetAllPods(), true)
			reachabilityAllow.ExpectAllEgress("x/a", false)
			reachabilityAllow.Expect("x/a", "x/b", true)
			reachabilityAllow.AllowLoopback()

			ValidateOrFail(k8s, reachabilityAllow, NewScenario(82, 80, v1.ProtocolTCP), true)
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

			ns := "x"
			allowEgressPolicy := GetAllowEgressForTarget(metav1.LabelSelector{MatchLabels: targetLabels})
			CreateOrUpdatePolicy(k8s, allowEgressPolicy, ns, true)

			allowEgressReachability := NewReachability(GetAllPods(), true)
			ValidateOrFail(k8s, allowEgressReachability, NewScenario(82, 80, v1.ProtocolTCP), true)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")

			denyAllIngressPolicy := GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: targetLabels})
			CreateOrUpdatePolicy(k8s, denyAllIngressPolicy, ns, true)

			denyIngressToXReachability := NewReachability(GetAllPods(), true)
			denyIngressToXReachability.ExpectAllIngress("x/a", false)
			denyIngressToXReachability.AllowLoopback()
			ValidateOrFail(k8s, denyIngressToXReachability, NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only SCTP [Feature:Netpol] [Feature:SCTP]", func() {
			ns := "x"
			policy := GetAllowIngressOnProtocolByPort("allow-only-sctp-ingress-on-port-81", v1.ProtocolSCTP, map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Creating a network policy for the server which allows traffic only via SCTP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()
			ValidateOrFail(k8s, reachability, NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only UDP [Feature:Netpol] [Feature:UDP]", func() {
			ns := "x"
			policy := GetAllowIngressOnProtocolByPort("allow-only-udp-ingress-on-port-81", v1.ProtocolUDP, map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Creating a network policy for the server which allows traffic only via UDP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := NewReachability(GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()
			ValidateOrFail(k8s, reachability, NewScenario(82, 81, v1.ProtocolTCP), true)
		})
	})
})
