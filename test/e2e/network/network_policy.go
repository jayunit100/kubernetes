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

package network

import (
	"context"
	"fmt"
	utilnet "k8s.io/utils/net"
	"time"

	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"

	v1 "k8s.io/api/core/v1"

	"github.com/onsi/ginkgo"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	netpol "k8s.io/kubernetes/test/e2e/network/policy/utils"
)

/*
The following Network Policy tests verify that policy object definitions
are correctly enforced by a networking plugin. It accomplishes this by launching
a simple netcat server, and two clients with different
attributes. Each test case creates a network policy which should only allow
connections from one of the clients. The test then asserts that the clients
failed or successfully connected as expected.
*/

var _ = SIGDescribe("NetworkPolicy [LinuxOnly]", func() {
	f := framework.NewDefaultFramework("network-policy")

	var k8s *netpol.Kubernetes
	backgroundInit := false
	scenario := netpol.NewScenario()
	ginkgo.BeforeEach(func() {
		// The code in here only runs once bc it checks if things are nil
		if k8s == nil {
			var err error
			framework.Logf("instantiating Kubernetes helper")
			k8s, err = netpol.NewKubernetes()

			framework.ExpectNoError(err, "Unable to instantiate Kubernetes helper")
			framework.Logf("bootstrapping cluster: ensuring namespaces, deployments, and pods exist and are ready")
			// TODO why does this error on the first test case?
			//err = k8s.Bootstrap(netpol.NetpolTestNamespaces, netpol.NetpolTestPods, netpol.GetAllPods())
			//framework.ExpectNoError(err, "Unable to bootstrap cluster")
			k8s.Bootstrap(netpol.NetpolTestNamespaces, netpol.NetpolTestPods, netpol.GetAllPods())
			framework.Logf("finished bootstrapping cluster")

			//TODO move to different location for unit test
			if netpol.PodString("x/a") != netpol.NewPodString("x", "a") {
				framework.Failf("Namespace, pod representation doesn't match PodString type")
			}
		}
		if !backgroundInit {
			p := netpol.GetRandomIngressPolicies(21)
			for i := 0; i < 20; i++ {
				_, err := f.ClientSet.NetworkingV1().NetworkPolicies("default").Create(context.TODO(), p[i], metav1.CreateOptions{})
				if err != nil {
					framework.Logf("unable to create netpol %+v: %+v", p[i], err)
				}
			}
			backgroundInit = true
		}
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			netpol.CleanPoliciesAndValidate(f, k8s, scenario, v1.ProtocolTCP)
		})

		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDenyIngress("deny-ingress")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDenyAll("deny-all")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:NetworkPolicy]", func() {
			allowedPods := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := netpol.GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := netpol.GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedPods := metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy := netpol.GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowIngressByNamespace("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]", func() {
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
			policy := netpol.GetAllowIngressByNamespaceOrPod("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces, podBAllowlisting)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.Expect("x/c", "x/a", false)

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
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
			policy := netpol.GetAllowIngressByNamespaceAndPod("allow-ns-y-podselector-and-nsselector", map[string]string{"pod": "a"}, allowedNamespaces, allowedPod)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("y/b", "x/a", true)
			reachability.Expect("z/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on Multiple PodSelectors and NamespaceSelectors [Feature:NetworkPolicy]", func() {
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
			policy := netpol.GetAllowIngressByNamespaceAndPod("allow-ns-y-z-pod-b-c", map[string]string{"pod": "a"}, allowedNamespaces, allowedPod)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.Expect("y/a", "x/a", false)
			reachability.Expect("z/a", "x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
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
			policy := netpol.GetAllowIngressByNamespaceAndPod("allow-ns-y-pod-a-via-namespace-pod-selector", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("y/a", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowPort81Policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "y"}, &netpol.Peer{Namespace: "x", Pod: "a"}, true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, allowPort81Policy, reachability, true, scenario)
		})

		ginkgo.It("should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowPort81Policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})

			reachabilityALLOW := netpol.NewReachability(scenario.AllPods, true)
			reachabilityALLOW.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachabilityALLOW.ExpectPeer(&netpol.Peer{Namespace: "y"}, &netpol.Peer{Namespace: "x", Pod: "a"}, true)
			reachabilityALLOW.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachabilityALLOW.AllowLoopback()

			ginkgo.By("Verifying traffic on port 81.")
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, allowPort81Policy, reachabilityALLOW, true, scenario)

			reachabilityDENY := netpol.NewReachability(scenario.AllPods, true)
			reachabilityDENY.ExpectAllIngress("x/a", false)
			reachabilityDENY.AllowLoopback()

			ginkgo.By("Verifying traffic on port 80.")
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, allowPort81Policy, reachabilityDENY, false, scenario)

			allowPort80Policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 80})

			ginkgo.By("Verifying that we can add a policy to unblock port 80")
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, allowPort80Policy, reachabilityALLOW, false, scenario)
		})

		ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			policy := netpol.GetAllowIngress("allow-all")
			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := netpol.NewReachability(scenario.AllPods, true)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachability, false, scenario)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowIngressByPort("allow-all", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81-tcp"})

			// WARNING ! Since we are adding a port rule, that means that the lack of a
			// pod selector will cause this policy to target the ENTIRE namespace
			ginkgo.By("Blocking all ports other then 81 in the entire namespace")

			reachabilityPort81 := netpol.NewReachability(scenario.AllPods, true)

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachabilityPort81, true, scenario)

			// disallow all traffic to the x namespace
			reachabilityPort80 := netpol.NewReachability(scenario.AllPods, true)
			reachabilityPort80.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachabilityPort80.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, nil, reachabilityPort80, false, scenario)
		})

		ginkgo.It("should allow ingress access from namespace on one named port [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})

			reachability := netpol.NewReachability(scenario.AllPods, true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			ginkgo.By("Verify that port 80 is allowed for namespace y")
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)

			ginkgo.By("Verify that port 81 is blocked for all namespaces including y")
			reachabilityFAIL := netpol.NewReachability(scenario.AllPods, true)
			reachabilityFAIL.ExpectAllIngress("x/a", false)
			reachabilityFAIL.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachabilityFAIL, false, scenario)
		})

		ginkgo.It("should allow egress access on one named port [Feature:NetworkPolicy]", func() {
			ginkgo.By("validating egress from port 82 to port 80")
			policy := netpol.GetAllowEgressByPort("allow-egress", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			// By adding a port rule to the egress class we now restrict egress to only work on port 80.
			// TODO What about DNS -- we removed that check.  Write a higher level DNS checking test
			//   which can be used to fulfill that requirement.

			reachabilityPort80 := netpol.NewReachability(scenario.AllPods, true)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachabilityPort80, true, scenario)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachabilityPort81 := netpol.NewReachability(scenario.AllPods, true)
			reachabilityPort81.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachabilityPort81.AllowLoopback()

			// no input policy, don't erase the last one...
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, nil, reachabilityPort81, false, scenario)
		})

		ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Using the simplest possible mutation: start with allow all, then switch to deny all")
			// part 1) allow all
			policy := netpol.GetAllowIngress("allow-all-mutate-to-deny-all")
			reachability := netpol.NewReachability(scenario.AllPods, true)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachability, true, scenario)

			// part 2) update the policy to deny all
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			reachability = netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachability, false, scenario)
		})

		ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
			netpol.ResetNamespaceLabels(f, "y")
			defer netpol.ResetNamespaceLabels(f, "y")

			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns2": "updated",
				},
			}

			policy := netpol.GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)

			// add a new label, we'll remove it after this test is completed
			updatedLabels := map[string]string{
				"ns":  "y",
				"ns2": "updated",
			}
			netpol.UpdateNamespaceLabels(f, "y", updatedLabels)

			// anything from namespace 'y' should be able to get to x/a
			reachability.ExpectPeer(&netpol.Peer{Namespace: "y"}, &netpol.Peer{}, true)

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should allow ingress access from updated pod [Feature:NetworkPolicy]", func() {
			netpol.ResetDeploymentPodLabels(f, "x", "b")
			defer netpol.ResetDeploymentPodLabels(f, "x", "b")

			// add a new label, we'll remove it after this test is done
			matchLabels := map[string]string{"pod": "b", "pod2": "updated"}
			allowedLabels := &metav1.LabelSelector{MatchLabels: matchLabels}
			policy := netpol.GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)

			// now update label in x namespace and pod b
			netpol.AddDeploymentPodLabels(f, "x", "b", matchLabels)

			ginkgo.By("There is connection between x/b to x/a when label is updated")
			reachability.Expect("x/b", "x/a", true)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, nil, reachability, false, scenario)
		})

		ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
			netpol.ResetDeploymentPodLabels(f, "x", "a")
			defer netpol.ResetDeploymentPodLabels(f, "x", "a")

			policy := netpol.GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: map[string]string{"target": "isolated"}})

			reachability := netpol.NewReachability(scenario.AllPods, true)

			ginkgo.By("Verify that everything can reach x/a")
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, nil, reachability, true, scenario)

			netpol.AddDeploymentPodLabels(f, "x", "a", map[string]string{"target": "isolated"})

			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should work with Ingress, Egress specified together [Feature:NetworkPolicy]", func() {
			allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
			policy := netpol.GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)
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

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)

			ginkgo.By("validating that port 81 doesn't work")

			// meanwhile no traffic on 81 should work, since our egress policy is on 80
			reachability.ExpectAllEgress("x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, nil, reachability, false, scenario)
		})

		ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
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
			policy := netpol.GetAllowEgressByNamespaceAndPod("allow-to-ns-y-pod-a", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.Expect("x/a", "y/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)
		})

		ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
			policyAllowOnlyPort80 := netpol.GetAllowIngressByPort("allow-ingress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})

			ginkgo.By("The policy targets port 80 -- so let's make sure traffic on port 81 is blocked")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policyAllowOnlyPort80, reachability, true, scenario)

			ginkgo.By("Allowing all ports")

			reachabilityAll := netpol.NewReachability(scenario.AllPods, true)
			policyAllowAll := netpol.GetAllowIngress("allow-ingress")
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policyAllowAll, reachabilityAll, false, scenario)
		})

		ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowEgressByPort("allow-egress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})

			ginkgo.By("Making sure ingress doesn't work other than port 80")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachability, true, scenario)

			ginkgo.By("Allowing all ports")

			reachabilityAll := netpol.NewReachability(scenario.AllPods, true)
			policyAllowAll := netpol.GetAllowEgress()
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policyAllowAll, reachabilityAll, false, scenario)
		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the server which denies all traffic.")
			policy := netpol.GetDenyAll("deny-all")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policy, reachability, true, scenario)

			err := k8s.CleanNetworkPolicies(scenario.Namespaces)
			time.Sleep(3 * time.Second)
			if err != nil {
				ginkgo.Fail(fmt.Sprintf("%v", err))
			}
			reachabilityAll := netpol.NewReachability(scenario.AllPods, true)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, nil, reachabilityAll, false, scenario)
		})

		ginkgo.It("should allow egress access to server in CIDR block [Feature:NetworkPolicy]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR
			podList, err := f.ClientSet.CoreV1().Pods("y").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to list pods in namespace y")
			pod := podList.Items[0]

			hostMask := 32
			if utilnet.IsIPv6String(pod.Status.PodIP) {
				hostMask = 128
			}
			podServerCIDR := fmt.Sprintf("%s/%d", pod.Status.PodIP, hostMask)

			policyAllowCIDR := netpol.GetAllowEgressByCIDR("a", podServerCIDR)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.Expect("x/a", "y/b", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policyAllowCIDR, reachability, true, scenario)
		})

		ginkgo.It("should enforce except clause while egress access to server in CIDR block [Feature:NetworkPolicy]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to find pod x/a")
			podA := podList.Items[0]

			podServerAllowCIDR := fmt.Sprintf("%s/4", podA.Status.PodIP)

			podList, err = f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to find pod x/b")
			podB := podList.Items[0]

			podServerExceptList := []string{fmt.Sprintf("%s/32", podB.Status.PodIP)}
			policyAllowCIDR := netpol.GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.Expect("x/a", "x/b", false)

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policyAllowCIDR, reachability, true, scenario)
		})

		ginkgo.It("should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed [Feature:NetworkPolicy]", func() {
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
			policyAllowCIDR := netpol.GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.Expect("x/a", "x/b", false)

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, policyAllowCIDR, reachability, true, scenario)

			podBIP := fmt.Sprintf("%s/32", podB.Status.PodIP)
			//// Create NetworkPolicy which allows access to the podServer using podServer's IP in allow CIDR.
			allowPolicy := netpol.GetAllowEgressByCIDR("a", podBIP)

			reachabilityAllow := netpol.NewReachability(scenario.AllPods, true)
			reachabilityAllow.ExpectAllEgress("x/a", false)
			reachabilityAllow.Expect("x/a", "x/b", true)
			reachabilityAllow.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, allowPolicy, reachabilityAllow, false, scenario)
		})

		ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:NetworkPolicy]", func() {
			/*
				Test steps:
				1. Verify every pod in every namespace can talk to each other
				2. Create and apply a policy to allow egress traffic to pod b
				3. Deny all Ingress traffic to Pod A in Namespace A (so that B cannot talk to A)
				4. Verify B->A: blocked
				5. Verify A->B: allowed
			*/
			allowAllIngressPolicy := netpol.GetAllowIngress("allow-all")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, allowAllIngressPolicy, reachability, true, scenario)

			ginkgo.By("Creating a network policy for pod-a which allows Egress traffic to pod-b.")

			allowEgressToBPolicy := netpol.GetAllowEgressByPod("a", "b")

			allowEgressToBReachability := netpol.NewReachability(scenario.AllPods, true)
			allowEgressToBReachability.ExpectAllEgress("x/a", false)
			allowEgressToBReachability.AllowLoopback()
			allowEgressToBReachability.Expect("x/a", "x/b", true)

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, allowEgressToBPolicy, allowEgressToBReachability, true, scenario)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")
			denyAllIngressPolicy := netpol.GetDenyIngress("deny-all")

			denyIngressToXReachability := netpol.NewReachability(scenario.AllPods, true)
			denyIngressToXReachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			denyIngressToXReachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 80, denyAllIngressPolicy, denyIngressToXReachability, true, scenario)
		})

		// NOTE: SCTP protocol is not in Kubernetes 1.19 so this test will fail locally.
		ginkgo.It("should not allow access by TCP when a policy specifies only SCTP [Feature:NetworkPolicy] [Feature:SCTP]", func() {
			policy := netpol.GetAllowIngressOnSCTPByPort("allow-only-sctp-ingress-on-port-81", map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			ginkgo.By("Creating a network policy for the server which allows traffic only via SCTP on port 81.")
			//protocolSCTP := v1.ProtocolSCTP
			//			//// WARNING ! Since we are adding a port rule, that means that the lack of a
			//			//// pod selector will cause this policy to target the ENTIRE namespace.....
			//			//policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
			//			//	//Port:     &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81"},
			//			//	Port:     &intstr.IntOrString{IntVal: 81},
			//			//	Protocol: &protocolSCTP,
			//			//}}

			// Probing with TCP, so all traffic should be dropped.
			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			//TODO check SCTP is not module is not available at time of testing
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachability, true, scenario)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only UDP [Feature:NetworkPolicy] [Feature:UDP]", func() {
			policy := netpol.GetAllowIngressOnProtocolByPort(
				"allow-only-udp-ingress-on-port-81",
				v1.ProtocolUDP,
				map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81},
			)
			ginkgo.By("Creating a network policy for the server which allows traffic only via UDP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()
			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolTCP, 82, 81, policy, reachability, true, scenario)
		})
	})
})

var _ = SIGDescribe("NetworkPolicy [Feature:SCTPConnectivity][LinuxOnly][Disruptive]", func() {
	f := framework.NewDefaultFramework("sctp-network-policy")
	var k8s *netpol.Kubernetes
	var err error
	scenario := netpol.NewScenario()

	ginkgo.BeforeEach(func() {
		if k8s == nil {
			k8s, err = netpol.NewKubernetes()
			framework.ExpectNoError(err, "Error occurred while getting k8s client")
			k8s.Bootstrap(netpol.NetpolTestNamespaces, netpol.NetpolTestPods, netpol.GetAllPods())
		}
		// Windows does not support network policies.
		e2eskipper.SkipIfNodeOSDistroIs("windows")
	})

	ginkgo.Context("NetworkPolicy between server and client using SCTP", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			netpol.CleanPoliciesAndValidate(f, k8s, scenario, v1.ProtocolSCTP)
		})

		ginkgo.It("should support a 'default-deny' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDenyIngress("deny-ingress")

			reachability := netpol.NewReachability(scenario.AllPods, false)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolSCTP, 82, 80, policy, reachability, false, scenario)
		})
	})
})

var _ = SIGDescribe("NetworkPolicy [Feature:UDPConnectivity][LinuxOnly][Disruptive]", func() {
	f := framework.NewDefaultFramework("udp-network-policy")
	var k8s *netpol.Kubernetes
	var err error
	scenario := netpol.NewScenario()

	ginkgo.BeforeEach(func() {
		if k8s == nil {
			k8s, err = netpol.NewKubernetes()
			framework.ExpectNoError(err, "Error occurred while getting k8s client")
			k8s.Bootstrap(netpol.NetpolTestNamespaces, netpol.NetpolTestPods, netpol.GetAllPods())
		}
		// Windows does not support network policies.
		e2eskipper.SkipIfNodeOSDistroIs("windows")
	})

	ginkgo.Context("NetworkPolicy between server and client using UDP", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			netpol.CleanPoliciesAndValidate(f, k8s, scenario, v1.ProtocolUDP)
		})
		ginkgo.It("should support a 'default-deny' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDenyIngress("deny-ingress")

			reachability := netpol.NewReachability(scenario.AllPods, true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFailFunc(k8s, f, "x", v1.ProtocolUDP, 82, 80, policy, reachability, false, scenario)
		})
	})
})
