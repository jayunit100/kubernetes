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
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	utilnet "k8s.io/utils/net"
	"time"

	"github.com/onsi/ginkgo"

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
	ginkgo.BeforeEach(func() {
		// The code in here only runs once bc it checks if things are nil
		if k8s == nil {
			var err error
			framework.Logf("instantiating Kubernetes helper")
			k8s = netpol.NewKubernetes(f.ClientSet)

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

			p := netpol.GetRandomIngressPolicies(21)
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
			netpol.CleanPolicies(k8s, netpol.NetpolTestNamespaces)
			netpol.ValidateAllConnectivity(k8s, netpol.NewScenario(83, 80, v1.ProtocolTCP))
		})

		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

			policy := netpol.GetDenyIngress("deny-ingress")
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

			policy := netpol.GetDenyAll("deny-all")
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

			allowedPods := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy := netpol.GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := netpol.GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

			allowedPods := metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy := netpol.GetAllowIngressByPod("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowIngressByNamespace("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

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
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.Expect("x/c", "x/a", false)

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

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
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("y/b", "x/a", true)
			reachability.Expect("z/b", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on Multiple PodSelectors and NamespaceSelectors [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

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
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.Expect("y/a", "x/a", false)
			reachability.Expect("z/a", "x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 80, v1.ProtocolTCP)

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
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("y/a", "x/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ns := "x"
			scenario := netpol.NewScenario(82, 81, v1.ProtocolTCP)

			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowPort81Policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})
			netpol.CreateOrUpdatePolicy(k8s, allowPort81Policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "y"}, &netpol.Peer{Namespace: "x", Pod: "a"}, true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, scenario, true)
		})

		ginkgo.It("should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]", func() {
			ns := "x"
			ginkgo.By("Creating a network allowPort81Policy which only allows allow listed namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			allowPort81Policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 81})
			netpol.CreateOrUpdatePolicy(k8s, allowPort81Policy, ns, true)

			reachabilityALLOW := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityALLOW.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachabilityALLOW.ExpectPeer(&netpol.Peer{Namespace: "y"}, &netpol.Peer{Namespace: "x", Pod: "a"}, true)
			reachabilityALLOW.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachabilityALLOW.AllowLoopback()

			ginkgo.By("Verifying traffic on port 81.")
			netpol.ValidateOrFail(k8s, reachabilityALLOW, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)

			reachabilityDENY := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityDENY.ExpectAllIngress("x/a", false)
			reachabilityDENY.AllowLoopback()

			ginkgo.By("Verifying traffic on port 80.")
			netpol.ValidateOrFail(k8s, reachabilityDENY, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			allowPort80Policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{IntVal: 80})
			netpol.CreateOrUpdatePolicy(k8s, allowPort80Policy, ns, true)

			ginkgo.By("Verifying that we can add a policy to unblock port 80")
			netpol.ValidateOrFail(k8s, reachabilityALLOW, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			ns := "x"
			policy := netpol.GetAllowIngress("allow-all")
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
			ns := "x"
			policy := netpol.GetAllowIngressByPort("allow-all", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81-tcp"})
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			// WARNING ! Since we are adding a port rule, that means that the lack of a
			// pod selector will cause this policy to target the ENTIRE namespace
			ginkgo.By("Blocking all ports other then 81 in the entire namespace")

			reachabilityPort81 := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachabilityPort81, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)

			// disallow all traffic to the x namespace
			reachabilityPort80 := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityPort80.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachabilityPort80.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachabilityPort80, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access from namespace on one named port [Feature:NetworkPolicy]", func() {
			ns := "x"
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := netpol.GetAllowIngressByNamespaceAndPort("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels, &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			// disallow all traffic from the x or z namespaces
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "z"}, &netpol.Peer{Namespace: "x", Pod: "a"}, false)
			reachability.AllowLoopback()

			ginkgo.By("Verify that port 80 is allowed for namespace y")
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			ginkgo.By("Verify that port 81 is blocked for all namespaces including y")
			reachabilityFAIL := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityFAIL.ExpectAllIngress("x/a", false)
			reachabilityFAIL.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachabilityFAIL, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow egress access on one named port [Feature:NetworkPolicy]", func() {
			ginkgo.By("validating egress from port 82 to port 80")
			ns := "x"
			policy := netpol.GetAllowEgressByPort("allow-egress", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)
			// By adding a port rule to the egress class we now restrict egress to only work on port 80.
			// TODO What about DNS -- we removed that check.  Write a higher level DNS checking test
			//   which can be used to fulfill that requirement.

			reachabilityPort80 := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachabilityPort80, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachabilityPort81 := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityPort81.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachabilityPort81.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachabilityPort81, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Using the simplest possible mutation: start with allow all, then switch to deny all")
			// part 1) allow all
			ns := "x"
			policy := netpol.GetAllowIngress("allow-all-mutate-to-deny-all")
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)

			// part 2) update the policy to deny all
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachabilityDeny := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityDeny.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachabilityDeny.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachabilityDeny, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
			netpol.ResetNamespaceLabels(f, "y")
			defer netpol.ResetNamespaceLabels(f, "y")

			ns := "x"
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns2": "updated",
				},
			}
			policy := netpol.GetAllowIngressByNamespace("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			// add a new label, we'll remove it after this test is completed
			updatedLabels := map[string]string{
				"ns":  "y",
				"ns2": "updated",
			}
			netpol.UpdateNamespaceLabels(f, "y", updatedLabels)

			// anything from namespace 'y' should be able to get to x/a
			reachability.ExpectPeer(&netpol.Peer{Namespace: "y"}, &netpol.Peer{}, true)

			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should allow ingress access from updated pod [Feature:NetworkPolicy]", func() {
			netpol.ResetDeploymentPodLabels(f, "x", "b")
			defer netpol.ResetDeploymentPodLabels(f, "x", "b")

			// add a new label, we'll remove it after this test is done
			ns := "x"
			matchLabels := map[string]string{"pod": "b", "pod2": "updated"}
			allowedLabels := &metav1.LabelSelector{MatchLabels: matchLabels}
			policy := netpol.GetAllowIngressByPod("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedLabels)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			// now update label in x namespace and pod b
			netpol.AddDeploymentPodLabels(f, "x", "b", matchLabels)

			ginkgo.By("There is connection between x/b to x/a when label is updated")
			reachability.Expect("x/b", "x/a", true)
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
			netpol.ResetDeploymentPodLabels(f, "x", "a")
			defer netpol.ResetDeploymentPodLabels(f, "x", "a")

			ns := "x"
			policy := netpol.GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: map[string]string{"target": "isolated"}})
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Verify that everything can reach x/a")
			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			netpol.AddDeploymentPodLabels(f, "x", "a", map[string]string{"target": "isolated"})
			reachabilityIsolated := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityIsolated.ExpectAllIngress("x/a", false)
			reachabilityIsolated.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachabilityIsolated, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should work with Ingress, Egress specified together [Feature:NetworkPolicy]", func() {
			ns := "x"
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
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachabilityPort80 := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityPort80.ExpectAllIngress("x/a", false)
			reachabilityPort80.Expect("x/b", "x/a", true)
			reachabilityPort80.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachabilityPort80, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			ginkgo.By("validating that port 81 doesn't work")
			// meanwhile no egress traffic on 81 should work, since our egress policy is on 80
			reachabilityPort81 := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityPort81.ExpectAllIngress("x/a", false)
			reachabilityPort81.ExpectAllEgress("x/a", false)
			reachabilityPort81.Expect("x/b", "x/a", true)
			reachabilityPort81.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachabilityPort81, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
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
			policy := netpol.GetAllowEgressByNamespaceAndPod("allow-to-ns-y-pod-a", map[string]string{"pod": "a"}, allowedNamespaces, allowedPods)
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.Expect("x/a", "y/a", true)
			reachability.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
			ns := "x"
			policyAllowOnlyPort80 := netpol.GetAllowIngressByPort("allow-ingress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			netpol.CreateOrUpdatePolicy(k8s, policyAllowOnlyPort80, ns, true)

			ginkgo.By("The policy targets port 80 -- so let's make sure traffic on port 81 is blocked")

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)

			ginkgo.By("Allowing all ports")

			policyAllowAll := netpol.GetAllowIngress("allow-ingress")
			netpol.CreateOrUpdatePolicy(k8s, policyAllowAll, ns, true)

			reachabilityAll := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachabilityAll, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
			ns := "x"
			policyAllowPort80 := netpol.GetAllowEgressByPort("allow-egress-port-80", &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80-tcp"})
			netpol.CreateOrUpdatePolicy(k8s, policyAllowPort80, ns, true)

			ginkgo.By("Making sure ingress doesn't work other than port 80")

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)

			ginkgo.By("Allowing all ports")

			policyAllowAll := netpol.GetAllowEgress()
			netpol.CreateOrUpdatePolicy(k8s, policyAllowAll, ns, true)

			reachabilityAll := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachabilityAll, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the server which denies all traffic.")
			ns := "x"
			policy := netpol.GetDenyAll("deny-all")
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectPeer(&netpol.Peer{Namespace: "x"}, &netpol.Peer{}, false)
			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
			reachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			err := k8s.CleanNetworkPolicies(netpol.NetpolTestNamespaces)
			time.Sleep(3 * time.Second)
			framework.ExpectNoError(err, "unable to clean network policies")

			reachabilityAll := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, reachabilityAll, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
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
			ns := "x"
			netpol.CreateOrUpdatePolicy(k8s, policyAllowCIDR, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.Expect("x/a", "y/b", true)
			reachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
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
			ns := "x"
			policyAllowCIDR := netpol.GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)
			netpol.CreateOrUpdatePolicy(k8s, policyAllowCIDR, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.Expect("x/a", "x/b", false)

			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
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
			ns := "x"
			policyAllowCIDR := netpol.GetAllowEgressByCIDRExcept("a", podServerAllowCIDR, podServerExceptList)
			netpol.CreateOrUpdatePolicy(k8s, policyAllowCIDR, ns, true)

			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.Expect("x/a", "x/b", false)

			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			podBIP := fmt.Sprintf("%s/32", podB.Status.PodIP)
			//// Create NetworkPolicy which allows access to the podServer using podServer's IP in allow CIDR.
			allowPolicy := netpol.GetAllowEgressByCIDR("a", podBIP)
			netpol.CreateOrUpdatePolicy(k8s, allowPolicy, ns, true)

			reachabilityAllow := netpol.NewReachability(netpol.GetAllPods(), true)
			reachabilityAllow.ExpectAllEgress("x/a", false)
			reachabilityAllow.Expect("x/a", "x/b", true)
			reachabilityAllow.AllowLoopback()

			netpol.ValidateOrFail(k8s, reachabilityAllow, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:NetworkPolicy]", func() {
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
			allowEgressPolicy := netpol.GetAllowEgressForTarget(metav1.LabelSelector{MatchLabels: targetLabels})
			netpol.CreateOrUpdatePolicy(k8s, allowEgressPolicy, ns, true)

			allowEgressReachability := netpol.NewReachability(netpol.GetAllPods(), true)
			netpol.ValidateOrFail(k8s, allowEgressReachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")

			denyAllIngressPolicy := netpol.GetDenyIngressForTarget(metav1.LabelSelector{MatchLabels: targetLabels})
			netpol.CreateOrUpdatePolicy(k8s, denyAllIngressPolicy, ns, true)

			denyIngressToXReachability := netpol.NewReachability(netpol.GetAllPods(), true)
			denyIngressToXReachability.ExpectAllIngress("x/a", false)
			denyIngressToXReachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, denyIngressToXReachability, netpol.NewScenario(82, 80, v1.ProtocolTCP), true)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only SCTP [Feature:NetworkPolicy] [Feature:SCTP]", func() {
			ns := "x"
			policy := netpol.GetAllowIngressOnProtocolByPort("allow-only-sctp-ingress-on-port-81", v1.ProtocolSCTP, map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Creating a network policy for the server which allows traffic only via SCTP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})

		ginkgo.It("should not allow access by TCP when a policy specifies only UDP [Feature:NetworkPolicy] [Feature:UDP]", func() {
			ns := "x"
			policy := netpol.GetAllowIngressOnProtocolByPort("allow-only-udp-ingress-on-port-81", v1.ProtocolUDP, map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal: 81})
			netpol.CreateOrUpdatePolicy(k8s, policy, ns, true)

			ginkgo.By("Creating a network policy for the server which allows traffic only via UDP on port 81.")

			// Probing with TCP, so all traffic should be dropped.
			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.AllowLoopback()
			netpol.ValidateOrFail(k8s, reachability, netpol.NewScenario(82, 81, v1.ProtocolTCP), true)
		})
	})
})

//var _ = SIGDescribe("NetworkPolicy [Feature:SCTPConnectivity][LinuxOnly][Disruptive]", func() {
//	f := framework.NewDefaultFramework("sctp-network-policy")
//	var k8s *netpol.Kubernetes
//	scenario := netpol.NewScenario()
//
//	ginkgo.BeforeEach(func() {
//		if k8s == nil {
//			k8s = netpol.NewKubernetes(f.ClientSet)
//			k8s.Bootstrap(netpol.NetpolTestNamespaces, netpol.NetpolTestPods, netpol.GetAllPods())
//		}
//		// Windows does not support network policies.
//		e2eskipper.SkipIfNodeOSDistroIs("windows")
//	})
//
//	ginkgo.Context("NetworkPolicy between server and client using SCTP", func() {
//		ginkgo.BeforeEach(func() {
//			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
//			netpol.CleanPoliciesAndValidate(f, k8s, scenario, v1.ProtocolSCTP)
//		})
//
//		ginkgo.It("should support a 'default-deny' policy [Feature:NetworkPolicy]", func() {
//			policy := netpol.GetDenyIngress("deny-ingress")
//
//			reachability := netpol.NewReachability(netpol.GetAllPods(), false)
//			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
//			reachability.AllowLoopback()
//
//			netpol.ValidateOrFail(k8s, f, "x", v1.ProtocolSCTP, 82, 80, policy, reachability, false, scenario)
//		})
//	})
//})
//
//var _ = SIGDescribe("NetworkPolicy [Feature:UDPConnectivity][LinuxOnly][Disruptive]", func() {
//	f := framework.NewDefaultFramework("udp-network-policy")
//	var k8s *netpol.Kubernetes
//	scenario := netpol.NewScenario()
//
//	ginkgo.BeforeEach(func() {
//		if k8s == nil {
//			k8s = netpol.NewKubernetes(f.ClientSet)
//			k8s.Bootstrap(netpol.NetpolTestNamespaces, netpol.NetpolTestPods, netpol.GetAllPods())
//		}
//		// Windows does not support network policies.
//		e2eskipper.SkipIfNodeOSDistroIs("windows")
//	})
//
//	ginkgo.Context("NetworkPolicy between server and client using UDP", func() {
//		ginkgo.BeforeEach(func() {
//			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
//			netpol.CleanPoliciesAndValidate(f, k8s, scenario, v1.ProtocolUDP)
//		})
//		ginkgo.It("should support a 'default-deny' policy [Feature:NetworkPolicy]", func() {
//			policy := netpol.GetDenyIngress("deny-ingress")
//
//			reachability := netpol.NewReachability(netpol.GetAllPods(), true)
//			reachability.ExpectPeer(&netpol.Peer{}, &netpol.Peer{Namespace: "x"}, false)
//			reachability.AllowLoopback()
//
//			netpol.ValidateOrFail(k8s, f, "x", v1.ProtocolUDP, 82, 80, policy, reachability, false, scenario)
//		})
//	})
//})
