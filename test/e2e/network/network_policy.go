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
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	e2epod "k8s.io/kubernetes/test/e2e/framework/pod"
	e2eskipper "k8s.io/kubernetes/test/e2e/framework/skipper"
	imageutils "k8s.io/kubernetes/test/utils/image"
	netpol "k8s.io/kubernetes/test/e2e/network/policy/utils"

	"encoding/json"

	"fmt"

	"github.com/onsi/ginkgo"
)

/*
The following Network Policy tests verify that policy object definitions
are correctly enforced by a networking plugin. It accomplishes this by launching
a simple netcat server, and two clients with different
attributes. Each test case creates a network policy which should only allow
connections from one of the clients. The test then asserts that the clients
failed or successfully connected as expected.
*/

type Scenario struct {
	pods []string
	namespaces []string
	p80 int
	p81 int
	allPods []netpol.PodString
	podIPs map[string]string
}

// NewScenario creates a new test scenario.
func NewScenario() *Scenario{
	s := &Scenario{}
	s.p80 = 80
	s.p81 = 81
	s.pods = []string{"a", "b", "c"}
	s.namespaces = []string{"x", "y", "z"}
	s.podIPs = make(map[string]string, len(s.pods)*len(s.namespaces))
	for _, podName := range s.pods {
		for _, ns := range s.namespaces {
			s.allPods = append(s.allPods, netpol.NewPod(ns, podName))
		}
	}
	return s
}

/**

KUBERNETES_SERVICE_HOST=127.0.0.1
KUBERNETES_SERVICE_PORT=32768
./_output/local/bin/linux/amd64/e2e.test \
--provider=local \
--ginkgo.focus="NetworkPolicy" \
--kubeconfig=/home/ubuntu/.kube/config

 */

var _ = SIGDescribe("NetworkPolicy [LinuxOnly]", func() {
	var service *v1.Service
	var podServer *v1.Pod
	var podServerLabelSelector string

	f := framework.NewDefaultFramework("network-policy")

	var scenario *Scenario
	var k8s *netpol.Kubernetes


	ginkgo.BeforeSuite(func() {
		scenario = NewScenario()
		var err error
		k8s, err = netpol.NewKubernetes()
		if err != nil {
			ginkgo.Fail(fmt.Sprintf("error initializing k8s client %v", err))
		}
	})
	ginkgo.BeforeEach(func() {
		// Windows does not support network policies.
		e2eskipper.SkipIfNodeOSDistroIs("windows")
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.AfterEach(func() {
			// delete all network policies in namespaces x, y, z
		})

		cleanup := func() {
			// delete all namespaces
		}

		validateOrFailFunc := func(ns string, port int, policy *networkingv1.NetworkPolicy, reachability *netpol.Reachability, cleanPreviousPolicies bool){
			if cleanPreviousPolicies == true {
				cleanup()
			}
			// TODO: DELETE ALL NETWORK POLICIES BEFORE RUNNING THIS TEST...
			if policy != nil {
				fmt.Println("NETPOL creating ", policy.Name)
				_, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), policy, metav1.CreateOptions{})
				if err != nil {
					fmt.Println("NETPOL failed create, trying to update... ", policy.Name)
					_, err := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Update(context.TODO(), policy, metav1.UpdateOptions{})
					if err != nil {
						ginkgo.Fail("NETPOL failed creating policy")
					}
				}
			}
			ginkgo.By("Validating reachability matrix")
			netpol.Validate(k8s, reachability, port)
			if _, wrong, _ := reachability.Summary(); wrong != 0 {
				ginkgo.Fail("Had more then one wrong result in the reachability matrix.")
			}
		}
		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDefaultDenyIngressPolicy("deny-ingress")

			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			// allow loopback
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
			reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)

			validateOrFailFunc("x", 80, policy, reachability, true)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:NetworkPolicy]", func() {
			// TODO, should we have a positive control before this test runs in GinkoEach?
			policy := netpol.GetDefaultALLDenyPolicy("deny-all")
			reachability := netpol.NewReachability(scenario.allPods, false)

			// allow loopback
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
			reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)

			validateOrFailFunc("x", 80, policy, reachability,true)

			// TODO, should we have a positive control before this test runs in GinkoEach?
		})

		ginkgo.It("should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:NetworkPolicy]", func() {
			allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-selector",  map[string]string{"pod": "a"}, allowedPodLabels )

			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), true)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			// allow loopback
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
			reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)
			validateOrFailFunc("x", 80, policy, reachability,true)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "y"},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector",  map[string]string{"pod": "a"}, allowedLabels)

			// allow all traffic from the x,y,z namespaces
			reachability := netpol.NewReachability(scenario.allPods, true)

			// disallow all traffic from the x or z namespaces
			for _,nn := range []string{"x","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)

			validateOrFailFunc("x", 80, policy, reachability,true)
		})

		ginkgo.It("should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-match-selector",  map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.allPods, true)
			// dissallow anything to A that isn't pod B.
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			// loopback
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, policy, reachability,true)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector",map[string]string{"pod":"x"}, allowedNamespaces)
			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			for _,nn := range []string{"x","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			validateOrFailFunc("x", 80,  policy, reachability,true)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector",map[string]string{"pod":"x"}, allowedNamespaces)
			// Appending to an ingress rule is an *OR* operation, which broadens the policy to allow more traffic.
			// Now we add a second ingress rule to the policy, which means there are two ways to be whitelisted.
			// 1) via ns:y (Above)
			// 2) via pod:b (defined here)
			podBWhitelisting := networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "b",
					},
				},
			}
			policy.Spec.Ingress = append(policy.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: []networkingv1.NetworkPolicyPeer{
				podBWhitelisting,
			}})

			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces.. but allow 'pod:b' and 'ns:y'
			for _,nn := range []string{"x","z"} {
				for _, pp := range []string{"a", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			validateOrFailFunc("x", 80, policy, reachability,true)
		})

		// TODO We probably should have a test for multiple ns and pod filters.

		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			ginkgo.By("enforcing policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
				allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector",map[string]string{"pod":"x"}, allowedNamespaces)
			// Adding a namespace filter to a networkpolicy ingressRule will tighten the security boundary.
			// In this case, now ONLY y/b will be allowed.
			policy.Spec.Ingress[0].From[0].NamespaceSelector = &metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod": "b",
						},
			}
			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces.. but allow 'specifically' y/b.
			for _,nn := range []string{"x","z"} {
				for _, pp := range []string{"a","b","c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), pp=="b" && nn=="y")
				}
			}
			validateOrFailFunc("x", 80, policy, reachability,true)
		})

		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which only allows whitelisted namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "y"},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-81",  map[string]string{"pod": "a"}, allowedLabels)

			// allow all traffic from the x,y,z namespaces
			reachability := netpol.NewReachability(scenario.allPods, true)

			// disallow all traffic from the x or z namespaces
			for _,nn := range []string{"x","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)

			policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{IntVal: 81},
			}}

			// 1) Make sure now that port 81 works ok for the y namespace...
			validateOrFailFunc("x", 81, policy, reachability,false)


			// 2) Verify that port 80 doesnt work for any namespace (other then loopback)
			ginkgo.By("Verifying that all traffic to another port, 80, is blocked.")
			reachability = netpol.NewReachability(scenario.allPods, false)
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, policy, reachability,false)


			// 3) Verify that we can stack a policy to unblock port 80

			// Note that this final stacking test implements the
			// "should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]"
			// test specification, as it has already setup a set of policies which allowed some, but not all traffic.
			// Now we will add another policy for port 80, and verify that it is unblocked...
			ginkgo.By("Verifying that we can stack a policy to unblock port 80")
			policy2 := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-80",  map[string]string{"pod": "a"}, allowedLabels)
			policy2.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{IntVal: 80},
			}}
			validateOrFailFunc("x", 80, policy, reachability,false)
		})

		ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			policy := netpol.GetAllowAll("allow-all")
			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 80, policy, reachability, true)
			validateOrFailFunc("x", 81, policy, reachability, false )
		})

		ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowAll("allow-all-on-81")

			// Add a 'port' rule to the AllowAll ingress type, so now only 81 is valid.
			policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81"},
			}}

			// disallow all traffic from the x or z namespaces
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 81, policy, reachability,true)

			// disallow all traffic from the x or z namespaces
			reachability80 := netpol.NewReachability(scenario.allPods, false)
			reachability80.Expect("x/a","x/a",true)
			validateOrFailFunc("x", 80, nil, reachability,false)

		})

		ginkgo.It("should allow ingress access from namespace on one named port [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns":"y"},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-80",  map[string]string{"pod": "a"}, allowedLabels)
			policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
			}}

			reachability := netpol.NewReachability(scenario.allPods, true)

			// disallow all traffic from the x or z namespaces
			for _,nn := range []string{"x","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.NewPod(nn,pp), "x/a",false)
				}
			}

			validateOrFailFunc("x", 80, policy, reachability,false)

			// now validate 81 doesnt work, AT ALL, even for ns y... this validation might be overkill,
			// but still should be pretty fast.
			reachability = netpol.NewReachability(scenario.allPods, false)
			validateOrFailFunc("x", 81, policy, reachability,false)

		})

		// TODO In this test we remove the DNS check.  Write a higher level DNS checking test
		// which can be used to fulfill that requirement.
		ginkgo.It("should allow egress access on one named port [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowAll("egress-on-port")
			// By adding a port rule to the egress class we now restrict regress to only work on
			// port 80.  We add DNS support as well so that this can be done over a service.
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{

					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
						},
					},
				},
			}
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 80, policy, reachability,false)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachability81 := netpol.NewReachability(scenario.allPods, false)
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability81.Expect("x/a",netpol.NewPod(nn,pp), false)
				}
			}
			// no input policy, dont erase the last one...
			validateOrFailFunc("x", 81, nil, reachability81,false)
		})

		// The simplest possible mutation for this test - which is denyall->allow all.
		ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
			// part 1) allow all
			policy := netpol.GetAllowAll("allow-all-mutate-to-deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 81, policy, reachability,false)

			// part 2) update the policy and confirm deny all
			policy = netpol.GetDefaultALLDenyPolicy("allow-all-mutate-to-deny-all")
			reachability = netpol.NewReachability(scenario.allPods, false)
			reachability.Expect("x/a","x/a", true)
			reachability.Expect("x/b","x/b", true)
			reachability.Expect("x/b","x/b", true)

			validateOrFailFunc("x", 81, policy, reachability,false)

		})

		ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
			// add a new label, we'll remove it after this test is
			allowedLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"ns2": "updated"}}

			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector",  map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					// nobody can talk to a bc nothing has this ns2:updated label...
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, policy, reachability,true)

			// now mutate ns y to have this special new label.
			nsY, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), "y", metav1.GetOptions{})
			if err != nil {
				ginkgo.Fail("couldnt get ns")
			}
			nsY.ObjectMeta.Labels["ns2"] = "updated"
			_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), nsY, metav1.UpdateOptions{})
			// clean this out when done, remember we preserve pods/ns throughout
			cleanNewLabel := func() {
				delete(nsY.ObjectMeta.Labels, "ns2")
				_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), nsY, metav1.UpdateOptions{})
			}
			defer cleanNewLabel()
			if err != nil {
				ginkgo.Fail("couldnt update ns")
			}
			// now update our matrix - we want anything 'y' to be able to get to x/a...
			reachability.Expect(netpol.PodString("y/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("y/b"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("y/c"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, policy, reachability,false)

		})

		//  This function enables, and then denies, access to an updated pod. combining two previous test cases into
		//  one so as to reuse the same test harness.
		// 	so this implements ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
		//  as well.
		ginkgo.It("should allow ingress access from updated pod , and deny access to the updated pod as well [Feature:NetworkPolicy]", func() {
			// add a new label, we'll remove it after this test is
			allowedLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod2": "updated"}}

			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-ns-selector",  map[string]string{"pod": "a"}, allowedLabels)

			// 1) Confirm that traffic is denied because the pod2:updated hasn't been applied to podB yet.
			// We'll apply that in step (2).
			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					// nobody can talk to a bc nothing has this ns2:updated label...
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, policy, reachability,true)

			// (2) Now confirm that traffic from this pod is enabled by adding the label
			// now mutate pod to to have this special new label.
			podB, err := f.ClientSet.CoreV1().Pods("x").Get(context.TODO(), "x", metav1.GetOptions{})
			if err != nil {
				ginkgo.Fail("couldnt get pod")
			}
			podB.ObjectMeta.Labels["pod2"] = "updated"
			cleanNewLabel := func() {
				delete(podB.ObjectMeta.Labels, "pod2")
				_, err = f.ClientSet.CoreV1().Pods("x").Update(context.TODO(), podB, metav1.UpdateOptions{})
			}
			_, err = f.ClientSet.CoreV1().Pods("x").Update(context.TODO(), podB, metav1.UpdateOptions{})

			// clean this out when done, remember we preserve pods/ns throughout
			if err != nil {
				ginkgo.Fail("couldnt update pod")
			}
			// now update our matrix - we want this 'b' pod to access x/a.
			reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, nil, reachability,false)

			// (3) Now validate that denial is recovered from removing the label...
			// delete this label, so we can confirm that removing it DENIES access to the pod,
			// i.e. this is the 'should deny ingress access to updated pod' case.
			cleanNewLabel()

			reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/a"), false)
			validateOrFailFunc("x", 80, nil, reachability,false)
		})

		// ingress NS + PORT
		// egress NS + PORT
		ginkgo.It("should work with Ingress,Egress specified together [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowAll("egress-on-port")

			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
						},
					},
				},
			}
			reachability := netpol.NewReachability(scenario.allPods, true)

			validateOrFailFunc("x", 80, policy, reachability,true)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachability81 := netpol.NewReachability(scenario.allPods, false)
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability81.Expect("x/a",netpol.NewPod(nn,pp), false)
				}
			}
			// no input policy, dont erase the last one...
			validateOrFailFunc("x", 81, nil, reachability81,false)
		})

		ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			policy := netpol.GetPolicyWithEgressRule("x","a", "y", "c")

			reachability := netpol.NewReachability(scenario.allPods, true)
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect("x/a",netpol.NewPod(nn,pp), false)
				}
			}
			reachability.Expect("x/a","x/a", true)
			reachability.Expect("x/a","y/c", true)

			validateOrFailFunc("x", 80, policy, reachability,true)

		})

		ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the server which allows traffic only from client-b.")
			policyAllowOnlyFromClientB := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "allow-from-client-b-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the Server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServerLabelSelector,
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					// Allow traffic only from "client-b"
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod-name": "client-b",
								},
							},
						}},
					}},
				},
			}

			policyAllowOnlyFromClientB, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowOnlyFromClientB, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowOnlyFromClientB.")
			defer cleanupNetworkPolicy(f, policyAllowOnlyFromClientB)

			ginkgo.By("Creating client-a which should not be able to contact the server.", func() {
				testCannotConnect(f, f.Namespace, "client-a", service, 80)
			})
			ginkgo.By("Creating client-b which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-b", service, 80)
			})

			ginkgo.By("Creating a network policy for the server which allows traffic from all clients.")
			policyIngressAllowAll := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					//Namespace: f.Namespace.Name,
					Name: "allow-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to all pods
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{{}},
				},
			}

			policyIngressAllowAll, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyIngressAllowAll, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyIngressAllowAll.")
			defer cleanupNetworkPolicy(f, policyIngressAllowAll)

			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})
			ginkgo.By("Creating client-b which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-b", service, 80)
			})
		})

		ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
			podServerB, serviceB := createServerPodAndService(f, f.Namespace, "server-b", []int{80})
			defer cleanupServerPodAndService(f, podServerB, serviceB)

			ginkgo.By("Waiting for pod ready", func() {
				err := e2epod.WaitTimeoutForPodReadyInNamespace(f.ClientSet, podServerB.Name, f.Namespace.Name, framework.PodStartTimeout)
				framework.ExpectNoError(err, "Error occurred while waiting for pod type: Ready.")
			})

			protocolUDP := v1.ProtocolUDP

			ginkgo.By("Creating client-a which should be able to contact the server before applying policy.", func() {
				testCanConnect(f, f.Namespace, "client-a", serviceB, 80)
			})

			ginkgo.By("Creating a network policy for the server which allows traffic only to server-a.")
			policyAllowOnlyToServerA := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "allow-to-server-a-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the "client-a"
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "client-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					// Allow traffic only to "server-a"
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								// Allow DNS look-ups
								{
									Protocol: &protocolUDP,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"pod-name": podServerLabelSelector,
										},
									},
								},
							},
						},
					},
				},
			}
			policyAllowOnlyToServerA, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowOnlyToServerA, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowOnlyToServerA.")
			defer cleanupNetworkPolicy(f, policyAllowOnlyToServerA)

			ginkgo.By("Creating client-a which should not be able to contact the server-b.", func() {
				testCannotConnect(f, f.Namespace, "client-a", serviceB, 80)
			})
			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

			ginkgo.By("Creating a network policy which allows traffic to all pods.")
			policyEgressAllowAll := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name: "allow-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to all pods
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
				},
			}

			policyEgressAllowAll, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyEgressAllowAll, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyEgressAllowAll.")
			defer cleanupNetworkPolicy(f, policyEgressAllowAll)

			ginkgo.By("Creating client-a which should be able to contact the server-b.", func() {
				testCanConnect(f, f.Namespace, "client-a", serviceB, 80)
			})
			ginkgo.By("Creating client-a which should be able to contact the server-a.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})
		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy for the server which denies all traffic.")
			policyDenyAll := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "deny-all",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Deny all traffic
					PodSelector: metav1.LabelSelector{},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					Ingress:     []networkingv1.NetworkPolicyIngressRule{},
				},
			}

			policyDenyAll, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyDenyAll, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyDenyAll.")

			ginkgo.By("Creating client-a which should not be able to contact the server.", func() {
				testCannotConnect(f, f.Namespace, "client-a", service, 80)
			})

			ginkgo.By("Creating a network policy for the server which allows traffic only from client-a.")
			policyAllowFromClientA := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "allow-from-client-a-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the Server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": podServerLabelSelector,
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					// Allow traffic from "client-a"
					Ingress: []networkingv1.NetworkPolicyIngressRule{{
						From: []networkingv1.NetworkPolicyPeer{{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod-name": "client-a",
								},
							},
						}},
					}},
				},
			}

			policyAllowFromClientA, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowFromClientA, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowFromClientA.")

			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

			ginkgo.By("Deleting the network policy allowing traffic from client-a")
			cleanupNetworkPolicy(f, policyAllowFromClientA)

			ginkgo.By("Creating client-a which should not be able to contact the server.", func() {
				testCannotConnect(f, f.Namespace, "client-a", service, 80)
			})

			ginkgo.By("Deleting the network policy denying all traffic.")
			cleanupNetworkPolicy(f, policyDenyAll)

			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

		})

		ginkgo.It("should allow egress access to server in CIDR block [Feature:NetworkPolicy]", func() {
			var serviceB *v1.Service
			var podServerB *v1.Pod

			protocolUDP := v1.ProtocolUDP

			// Getting podServer's status to get podServer's IP, to create the CIDR
			podServerStatus, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.TODO(), podServer.Name, metav1.GetOptions{})
			if err != nil {
				framework.ExpectNoError(err, "Error occurred while getting pod status.")
			}

			podServerCIDR := fmt.Sprintf("%s/32", podServerStatus.Status.PodIP)

			// Creating pod-b and service-b
			podServerB, serviceB = createServerPodAndService(f, f.Namespace, "pod-b", []int{80})
			ginkgo.By("Waiting for pod-b to be ready", func() {
				err := e2epod.WaitTimeoutForPodReadyInNamespace(f.ClientSet, podServerB.Name, f.Namespace.Name, framework.PodStartTimeout)
				framework.ExpectNoError(err, "Error occurred while waiting for pod type: Ready.")
			})
			defer cleanupServerPodAndService(f, podServerB, serviceB)

			// Wait for podServerB with serviceB to be ready
			err = e2epod.WaitForPodRunningInNamespace(f.ClientSet, podServerB)
			framework.ExpectNoError(err, "Error occurred while waiting for pod status in namespace: Running.")

			ginkgo.By("Creating client-a which should be able to contact the server-b.", func() {
				testCanConnect(f, f.Namespace, "client-a", serviceB, 80)
			})

			policyAllowCIDR := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "allow-client-a-via-cidr-egress-rule",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the Server
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "client-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					// Allow traffic to only one CIDR block.
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								// Allow DNS look-ups
								{
									Protocol: &protocolUDP,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									IPBlock: &networkingv1.IPBlock{
										CIDR: podServerCIDR,
									},
								},
							},
						},
					},
				},
			}

			policyAllowCIDR, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowCIDR, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowCIDR.")
			defer cleanupNetworkPolicy(f, policyAllowCIDR)

			ginkgo.By("Creating client-a which should not be able to contact the server-b.", func() {
				testCannotConnect(f, f.Namespace, "client-a", serviceB, 80)
			})
			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})
		})

		ginkgo.It("should enforce except clause while egress access to server in CIDR block [Feature:NetworkPolicy]", func() {
			protocolUDP := v1.ProtocolUDP

			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podServerStatus, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.TODO(), podServer.Name, metav1.GetOptions{})
			if err != nil {
				framework.ExpectNoError(err, "Error occurred while getting pod status.")
			}

			podServerAllowCIDR := fmt.Sprintf("%s/24", podServerStatus.Status.PodIP)
			// Exclude podServer's IP with an Except clause
			podServerExceptList := []string{fmt.Sprintf("%s/32", podServerStatus.Status.PodIP)}

			// client-a can connect to server prior to applying the NetworkPolicy
			ginkgo.By("Creating client-a which should be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

			policyAllowCIDRWithExcept := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "deny-client-a-via-except-cidr-egress-rule",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the client.
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "client-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					// Allow traffic to only one CIDR block except subnet which includes Server.
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								// Allow DNS look-ups
								{
									Protocol: &protocolUDP,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									IPBlock: &networkingv1.IPBlock{
										CIDR:   podServerAllowCIDR,
										Except: podServerExceptList,
									},
								},
							},
						},
					},
				},
			}

			policyAllowCIDRWithExcept, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowCIDRWithExcept, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowCIDRWithExcept.")
			defer cleanupNetworkPolicy(f, policyAllowCIDRWithExcept)

			ginkgo.By("Creating client-a which should no longer be able to contact the server.", func() {
				testCannotConnect(f, f.Namespace, "client-a", service, 80)
			})
		})

		ginkgo.It("should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed [Feature:NetworkPolicy]", func() {
			protocolUDP := v1.ProtocolUDP

			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podServerStatus, err := f.ClientSet.CoreV1().Pods(f.Namespace.Name).Get(context.TODO(), podServer.Name, metav1.GetOptions{})
			if err != nil {
				framework.ExpectNoError(err, "Error occurred while getting pod status.")
			}

			podServerAllowCIDR := fmt.Sprintf("%s/24", podServerStatus.Status.PodIP)
			podServerIP := fmt.Sprintf("%s/32", podServerStatus.Status.PodIP)
			// Exclude podServer's IP with an Except clause
			podServerExceptList := []string{podServerIP}

			// Create NetworkPolicy which blocks access to podServer with except clause.
			policyAllowCIDRWithExceptServerPod := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "deny-client-a-via-except-cidr-egress-rule",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the client.
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "client-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					// Allow traffic to only one CIDR block except subnet which includes Server.
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								// Allow DNS look-ups
								{
									Protocol: &protocolUDP,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									IPBlock: &networkingv1.IPBlock{
										CIDR:   podServerAllowCIDR,
										Except: podServerExceptList,
									},
								},
							},
						},
					},
				},
			}

			policyAllowCIDRWithExceptServerPodObj, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowCIDRWithExceptServerPod, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowCIDRWithExceptServerPod.")

			ginkgo.By("Creating client-a which should not be able to contact the server.", func() {
				testCannotConnect(f, f.Namespace, "client-a", service, 80)
			})

			// Create NetworkPolicy which allows access to the podServer using podServer's IP in allow CIDR.
			policyAllowCIDRServerPod := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "allow-client-a-via-cidr-egress-rule",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy to the client.
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "client-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					// Allow traffic to only one CIDR block which includes Server.
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								// Allow DNS look-ups
								{
									Protocol: &protocolUDP,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									IPBlock: &networkingv1.IPBlock{
										CIDR: podServerIP,
									},
								},
							},
						},
					},
				},
			}

			policyAllowCIDRServerPod, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowCIDRServerPod, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowCIDRServerPod.")
			defer cleanupNetworkPolicy(f, policyAllowCIDRServerPod)

			ginkgo.By("Creating client-a which should now be able to contact the server.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

			ginkgo.By("Deleting the network policy with except podServer IP which disallows access to podServer.")
			cleanupNetworkPolicy(f, policyAllowCIDRWithExceptServerPodObj)

			ginkgo.By("Creating client-a which should still be able to contact the server after deleting the network policy with except clause.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

			// Recreate the NetworkPolicy which contains the podServer's IP in the except list.
			policyAllowCIDRWithExceptServerPod, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowCIDRWithExceptServerPod, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowCIDRWithExceptServerPod.")
			defer cleanupNetworkPolicy(f, policyAllowCIDRWithExceptServerPod)

			ginkgo.By("Creating client-a which should still be able to contact the server after recreating the network policy with except clause.", func() {
				testCanConnect(f, f.Namespace, "client-a", service, 80)
			})

		})

		ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:NetworkPolicy]", func() {
			var serviceA, serviceB *v1.Service
			var podA, podB *v1.Pod
			var err error

			protocolUDP := v1.ProtocolUDP

			// Before applying policy, communication should be successful between pod-a and pod-b
			podA, serviceA = createServerPodAndService(f, f.Namespace, "pod-a", []int{80})
			ginkgo.By("Waiting for pod-a to be ready", func() {
				err := e2epod.WaitTimeoutForPodReadyInNamespace(f.ClientSet, podA.Name, f.Namespace.Name, framework.PodStartTimeout)
				framework.ExpectNoError(err, "Error occurred while waiting for pod type: Ready.")
			})
			ginkgo.By("Creating client pod-b which should be able to contact the server pod-a.", func() {
				testCanConnect(f, f.Namespace, "pod-b", serviceA, 80)
			})
			cleanupServerPodAndService(f, podA, serviceA)

			podB, serviceB = createServerPodAndService(f, f.Namespace, "pod-b", []int{80})
			ginkgo.By("Waiting for pod-b to be ready", func() {
				err := e2epod.WaitTimeoutForPodReadyInNamespace(f.ClientSet, podB.Name, f.Namespace.Name, framework.PodStartTimeout)
				framework.ExpectNoError(err, "Error occurred while waiting for pod type: Ready.")
			})
			ginkgo.By("Creating client pod-a which should be able to contact the server pod-b.", func() {
				testCanConnect(f, f.Namespace, "pod-a", serviceB, 80)
			})

			ginkgo.By("Creating a network policy for pod-a which allows Egress traffic to pod-b.")
			policyAllowToPodB := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "allow-pod-a-to-pod-b-using-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy on pod-a
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "pod-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
					// Allow traffic to server on pod-b
					Egress: []networkingv1.NetworkPolicyEgressRule{
						{
							Ports: []networkingv1.NetworkPolicyPort{
								// Allow DNS look-ups
								{
									Protocol: &protocolUDP,
									Port:     &intstr.IntOrString{Type: intstr.Int, IntVal: 53},
								},
							},
						},
						{
							To: []networkingv1.NetworkPolicyPeer{
								{
									PodSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"pod-name": "pod-b",
										},
									},
								},
							},
						},
					},
				},
			}

			policyAllowToPodB, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyAllowToPodB, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyAllowToPodB.")
			defer cleanupNetworkPolicy(f, policyAllowToPodB)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")
			policyDenyFromPodB := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: f.Namespace.Name,
					Name:      "deny-pod-b-to-pod-a-pod-selector",
				},
				Spec: networkingv1.NetworkPolicySpec{
					// Apply this policy on the server on pod-a
					PodSelector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"pod-name": "pod-a",
						},
					},
					PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
					// Deny traffic from all pods, including pod-b
					Ingress: []networkingv1.NetworkPolicyIngressRule{},
				},
			}

			policyDenyFromPodB, err = f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyDenyFromPodB, metav1.CreateOptions{})
			framework.ExpectNoError(err, "Error occurred while creating policy: policyDenyFromPodB.")
			defer cleanupNetworkPolicy(f, policyDenyFromPodB)

			ginkgo.By("Creating client pod-a which should be able to contact the server pod-b.", func() {
				testCanConnect(f, f.Namespace, "pod-a", serviceB, 80)
			})
			cleanupServerPodAndService(f, podB, serviceB)

			// Creating server pod with label "pod-name": "pod-a" to deny traffic from client pod with label "pod-name": "pod-b"
			podA, serviceA = createServerPodAndService(f, f.Namespace, "pod-a", []int{80})
			ginkgo.By("Waiting for pod-a to be ready", func() {
				err := e2epod.WaitTimeoutForPodReadyInNamespace(f.ClientSet, podA.Name, f.Namespace.Name, framework.PodStartTimeout)
				framework.ExpectNoError(err, "Error occurred while waiting for pod type: Ready.")
			})

			ginkgo.By("Creating client pod-b which should be able to contact the server pod-a.", func() {
				testCannotConnect(f, f.Namespace, "pod-b", serviceA, 80)
			})
			cleanupServerPodAndService(f, podA, serviceA)
		})

	})

})

func testCanConnect(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int) {
	ginkgo.By(fmt.Sprintf("Creating client pod %s that should successfully connect to %s.", podName, service.Name))
	podClient := createNetworkClientPod(f, ns, podName, service, targetPort)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podClient.Name))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(context.TODO(), podClient.Name, metav1.DeleteOptions{}); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()
	checkConnectivity(f, ns, podClient, service)
}

func testCannotConnect(f *framework.Framework, ns *v1.Namespace, podName string, service *v1.Service, targetPort int) {
	ginkgo.By(fmt.Sprintf("Creating client pod %s that should not be able to connect to %s.", podName, service.Name))
	podClient := createNetworkClientPod(f, ns, podName, service, targetPort)
	defer func() {
		ginkgo.By(fmt.Sprintf("Cleaning up the pod %s", podClient.Name))
		if err := f.ClientSet.CoreV1().Pods(ns.Name).Delete(context.TODO(), podClient.Name, metav1.DeleteOptions{}); err != nil {
			framework.Failf("unable to cleanup pod %v: %v", podClient.Name, err)
		}
	}()
	checkNoConnectivity(f, ns, podClient, service)
}

func checkConnectivity(f *framework.Framework, ns *v1.Namespace, podClient *v1.Pod, service *v1.Service) {
	framework.Logf("Waiting for %s to complete.", podClient.Name)
	err := e2epod.WaitForPodNoLongerRunningInNamespace(f.ClientSet, podClient.Name, ns.Name)
	framework.ExpectNoError(err, "Pod did not finish as expected.")

	framework.Logf("Waiting for %s to complete.", podClient.Name)
	err = e2epod.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)
	if err != nil {
		pods, policies, logs := collectPodsAndNetworkPolicies(f, podClient)
		framework.Failf("Pod %s should be able to connect to service %s, but was not able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t%v\n\n", podClient.Name, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

func checkNoConnectivity(f *framework.Framework, ns *v1.Namespace, podClient *v1.Pod, service *v1.Service) {
	framework.Logf("Waiting for %s to complete.", podClient.Name)
	err := e2epod.WaitForPodSuccessInNamespace(f.ClientSet, podClient.Name, ns.Name)

	// We expect an error here since it's a cannot connect test.
	// Dump debug information if the error was nil.
	if err == nil {
		pods, policies, logs := collectPodsAndNetworkPolicies(f, podClient)
		framework.Failf("Pod %s should not be able to connect to service %s, but was able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t %v\n\n", podClient.Name, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

func checkNoConnectivityByExitCode(f *framework.Framework, ns *v1.Namespace, podClient *v1.Pod, service *v1.Service) {
	err := e2epod.WaitForPodCondition(f.ClientSet, ns.Name, podClient.Name, "terminated", framework.PodStartTimeout, func(pod *v1.Pod) (bool, error) {
		statuses := pod.Status.ContainerStatuses
		if len(statuses) == 0 || statuses[0].State.Terminated == nil {
			return false, nil
		}
		if statuses[0].State.Terminated.ExitCode != 0 {
			return true, fmt.Errorf("pod %q container exited with code: %d", podClient.Name, statuses[0].State.Terminated.ExitCode)
		}
		return true, nil
	})
	// We expect an error here since it's a cannot connect test.
	// Dump debug information if the error was nil.
	if err == nil {
		pods, policies, logs := collectPodsAndNetworkPolicies(f, podClient)
		framework.Failf("Pod %s should not be able to connect to service %s, but was able to connect.\nPod logs:\n%s\n\n Current NetworkPolicies:\n\t%v\n\n Pods:\n\t%v\n\n", podClient.Name, service.Name, logs, policies.Items, pods)

		// Dump debug information for the test namespace.
		framework.DumpDebugInfo(f.ClientSet, f.Namespace.Name)
	}
}

func collectPodsAndNetworkPolicies(f *framework.Framework, podClient *v1.Pod) ([]string, *networkingv1.NetworkPolicyList, string) {
	// Collect pod logs when we see a failure.
	logs, logErr := e2epod.GetPodLogs(f.ClientSet, f.Namespace.Name, podClient.Name, "client")
	if logErr != nil && apierrors.IsNotFound(logErr) {
		// Pod may have already been removed; try to get previous pod logs
		logs, logErr = e2epod.GetPreviousPodLogs(f.ClientSet, f.Namespace.Name, podClient.Name, fmt.Sprintf("%s-container", podClient.Name))
	}
	if logErr != nil {
		framework.Logf("Error getting container logs: %s", logErr)
	}

	// Collect current NetworkPolicies applied in the test namespace.
	policies, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		framework.Logf("error getting current NetworkPolicies for %s namespace: %s", f.Namespace.Name, err)
	}
	// Collect the list of pods running in the test namespace.
	podsInNS, err := e2epod.GetPodsInNamespace(f.ClientSet, f.Namespace.Name, map[string]string{})
	if err != nil {
		framework.Logf("error getting pods for %s namespace: %s", f.Namespace.Name, err)
	}
	pods := []string{}
	for _, p := range podsInNS {
		pods = append(pods, fmt.Sprintf("Pod: %s, Status: %s\n", p.Name, p.Status.String()))
	}
	return pods, policies, logs
}

// Create a server pod with a listening container for each port in ports[].
// Will also assign a pod label with key: "pod-name" and label set to the given podName for later use by the network
// policy.
func createServerPodAndService(f *framework.Framework, namespace *v1.Namespace, podName string, ports []int) (*v1.Pod, *v1.Service) {
	// Because we have a variable amount of ports, we'll first loop through and generate our Containers for our pod,
	// and ServicePorts.for our Service.
	containers := []v1.Container{}
	servicePorts := []v1.ServicePort{}
	for _, port := range ports {
		// Build the containers for the server pod.
		containers = append(containers, v1.Container{
			Name:  fmt.Sprintf("%s-container-%d", podName, port),
			Image: imageutils.GetE2EImage(imageutils.Agnhost),
			Args:  []string{"porter"},
			Env: []v1.EnvVar{
				{
					Name:  fmt.Sprintf("SERVE_PORT_%d", port),
					Value: "foo",
				},
			},
			Ports: []v1.ContainerPort{
				{
					ContainerPort: int32(port),
					Name:          fmt.Sprintf("serve-%d", port),
				},
			},
			ReadinessProbe: &v1.Probe{
				Handler: v1.Handler{
					HTTPGet: &v1.HTTPGetAction{
						Path: "/",
						Port: intstr.IntOrString{
							IntVal: int32(port),
						},
						Scheme: v1.URISchemeHTTP,
					},
				},
			},
		})

		// Build the Service Ports for the service.
		servicePorts = append(servicePorts, v1.ServicePort{
			Name:       fmt.Sprintf("%s-%d", podName, port),
			Port:       int32(port),
			TargetPort: intstr.FromInt(port),
		})
	}

	ginkgo.By(fmt.Sprintf("Creating a server pod %s in namespace %s", podName, namespace.Name))
	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Create(context.TODO(), &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: podName + "-",
			Labels: map[string]string{
				"pod-name": podName,
			},
		},
		Spec: v1.PodSpec{
			Containers:    containers,
			RestartPolicy: v1.RestartPolicyNever,
		},
	}, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	framework.Logf("Created pod %v", pod.ObjectMeta.Name)

	svcName := fmt.Sprintf("svc-%s", podName)
	ginkgo.By(fmt.Sprintf("Creating a service %s for pod %s in namespace %s", svcName, podName, namespace.Name))
	svc, err := f.ClientSet.CoreV1().Services(namespace.Name).Create(context.TODO(), &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: svcName,
		},
		Spec: v1.ServiceSpec{
			Ports: servicePorts,
			Selector: map[string]string{
				"pod-name": podName,
			},
		},
	}, metav1.CreateOptions{})
	framework.ExpectNoError(err)
	framework.Logf("Created service %s", svc.Name)

	return pod, svc
}

func cleanupServerPodAndService(f *framework.Framework, pod *v1.Pod, service *v1.Service) {
	ginkgo.By("Cleaning up the server.")
	if err := f.ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{}); err != nil {
		framework.Failf("unable to cleanup pod %v: %v", pod.Name, err)
	}
	ginkgo.By("Cleaning up the server's service.")
	if err := f.ClientSet.CoreV1().Services(service.Namespace).Delete(context.TODO(), service.Name, metav1.DeleteOptions{}); err != nil {
		framework.Failf("unable to cleanup svc %v: %v", service.Name, err)
	}
}

// Create a client pod which will attempt a netcat to the provided service, on the specified port.
// This client will attempt a one-shot connection, then die, without restarting the pod.
// Test can then be asserted based on whether the pod quit with an error or not.
func createNetworkClientPod(f *framework.Framework, namespace *v1.Namespace, podName string, targetService *v1.Service, targetPort int) *v1.Pod {
	return createNetworkClientPodWithRestartPolicy(f, namespace, podName, targetService, targetPort, v1.RestartPolicyNever)
}

// Create a client pod which will attempt a netcat to the provided service, on the specified port.
// It is similar to createNetworkClientPod but supports specifying RestartPolicy.
func createNetworkClientPodWithRestartPolicy(f *framework.Framework, namespace *v1.Namespace, podName string, targetService *v1.Service, targetPort int, restartPolicy v1.RestartPolicy) *v1.Pod {
	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Create(context.TODO(), &v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: podName + "-",
			Labels: map[string]string{
				"pod-name": podName,
			},
		},
		Spec: v1.PodSpec{
			RestartPolicy: restartPolicy,
			Containers: []v1.Container{
				{
					Name:  "client",
					Image: imageutils.GetE2EImage(imageutils.BusyBox),
					Args: []string{
						"/bin/sh",
						"-c",
						fmt.Sprintf("for i in $(seq 1 5); do nc -vz -w 8 %s.%s %d && exit 0 || sleep 1; done; exit 1",
							targetService.Name, targetService.Namespace, targetPort),
					},
				},
			},
		},
	}, metav1.CreateOptions{})
	framework.ExpectNoError(err)

	return pod
}

// Patch pod with a map value
func updatePodLabel(f *framework.Framework, namespace *v1.Namespace, podName string, patchOperation string, patchPath string, patchValue map[string]string) *v1.Pod {
	type patchMapValue struct {
		Op    string            `json:"op"`
		Path  string            `json:"path"`
		Value map[string]string `json:"value,omitempty"`
	}
	payload := []patchMapValue{{
		Op:    patchOperation,
		Path:  patchPath,
		Value: patchValue,
	}}
	payloadBytes, err := json.Marshal(payload)
	framework.ExpectNoError(err)

	pod, err := f.ClientSet.CoreV1().Pods(namespace.Name).Patch(context.TODO(), podName, types.JSONPatchType, payloadBytes, metav1.PatchOptions{})
	framework.ExpectNoError(err)

	return pod
}

func cleanupNetworkPolicy(f *framework.Framework, policy *networkingv1.NetworkPolicy) {
	ginkgo.By("Cleaning up the policy.")
	if err := f.ClientSet.NetworkingV1().NetworkPolicies(policy.Namespace).Delete(context.TODO(), policy.Name, metav1.DeleteOptions{}); err != nil {
		framework.Failf("unable to cleanup policy %v: %v", policy.Name, err)
	}
}
