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
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/test/e2e/framework"
	netpol "k8s.io/kubernetes/test/e2e/network/policy/utils"

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

/**


cat << EOF > calico-conf.yaml
kind: Cluster
apiVersion: kind.sigs.k8s.io/v1alpha3
networking:
  disableDefaultCNI: true # disable kindnet
  podSubnet: 192.168.0.0/16 # set to Calico's default subnet
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

function install_k8s() {
    if kind delete cluster --name calico-test; then
        echo "deleted old kind cluster, creating a new one..."
    fi
    kind create cluster --name calico-test --config calico-conf.yaml
    export KUBECONFIG="$(kind get kubeconfig-path --name=calico-test)"
    for i in "cni-plugin" "node" "pod2daemon" "kube-controllers"; do
        echo "...$i"
    done
    chmod 755 ~/.kube/kind-config-kind
    export KUBECONFIG="$(kind get kubeconfig-path --name=calico-test)"
    until kubectl cluster-info;  do
        echo "`date`waiting for cluster..."
        sleep 2
    done
}

function install_calico() {
    kubectl get pods
    kubectl apply -f https://docs.projectcalico.org/manifests/calico.yaml
    kubectl -n kube-system set env daemonset/calico-node FELIX_IGNORELOOSERPF=true
    kubectl -n kube-system set env daemonset/calico-node FELIX_XDPENABLED=false
    sleep 5 ; kubectl -n kube-system get pods | grep calico-node
    echo "will wait for calico to start running now... "
    while true ; do
        kubectl -n kube-system get pods
        sleep 3
    done
}

install_k8s
install_calico

 */

var _ = SIGDescribe("NetworkPolicy [LinuxOnly]", func() {
	f := framework.NewDefaultFramework("network-policy")

	var k8s *netpol.Kubernetes
	var scenario *Scenario
	ginkgo.BeforeEach(func() {
		func() {
			scenario = NewScenario()
			if k8s == nil {
				k8s, _ = netpol.NewKubernetes()
				k8s.Bootstrap()
				k8s.CleanNetworkPolicies([]string{"x","y","z"})
			}
		}()
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.AfterEach(func() {
			// delete all network policies in namespaces x, y, z
		})

		cleanup := func() {
			// delete all namespaces
		}

		validateOrFailFunc := func(ns string, port int, policy *networkingv1.NetworkPolicy, reachability *netpol.Reachability, cleanPreviousPolicies bool) {
			if cleanPreviousPolicies == true {
				cleanup()
			}

			// TODO: DELETE ALL NETWORK POLICIES BEFORE RUNNING THIS TEST...
			if policy != nil {
				fmt.Println("NETPOL creating ", policy.Name)
				_, err1 := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), policy, metav1.CreateOptions{})
				if err1 != nil {
					fmt.Println("NETPOL failed create, trying to update... ", policy.Name)
					_, err2 := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Update(context.TODO(), policy, metav1.UpdateOptions{})
					if err2 != nil {
						ginkgo.Fail(fmt.Sprintf("NETPOL failed CREATING AND UPDATING policy .... %v .... %v", err1, err2))
					}
				}
			}
			ginkgo.By("Validating reachability matrix")
			netpol.Validate(k8s, reachability, port)
			if _, wrong, _ := reachability.Summary(); wrong != 0 {
				reachability.PrintSummary(true,true,true)
				ginkgo.Fail("Had more then one wrong result in the reachability matrix.")
			}
		}
		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDefaultDenyIngressPolicy("deny-ingress")

			reachability := netpol.NewReachability(scenario.allPods, true)
			
			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 80, policy, reachability, true)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:NetworkPolicy]", func() {
			// TODO, should we have a positive control before this test runs in GinkoEach?
			policy := netpol.GetDefaultALLDenyPolicy("deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress(netpol.PodString("x/a"),false)
			reachability.ExpectAllEgress(netpol.PodString("x/a"),false)

			validateOrFailFunc("x", 80, policy, reachability, true)

			// TODO, should we have a positive control before this test runs in GinkoEach?
		})

		ginkgo.It("should enforce policy to allow traffic from pods within server namespace based on PodSelector [Feature:NetworkPolicy]", func() {
			allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)

			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), true)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			// allow loopback
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
			reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)
			validateOrFailFunc("x", 80, policy, reachability, true)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "y"},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			// allow all traffic from the x,y,z namespaces
			reachability := netpol.NewReachability(scenario.allPods, true)

			// disallow all traffic from the x or z namespaces
			for _, nn := range []string{"x", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)

			validateOrFailFunc("x", 80, policy, reachability, true)
		})

		ginkgo.It("should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-match-selector", map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.allPods, true)
			// dissallow anything to A that isn't pod B.
			for _, nn := range []string{"x", "y", "z"} {
				for _, pp := range []string{"a", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			// loopback
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x", 80, policy, reachability, true)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector", map[string]string{"pod": "x"}, allowedNamespaces)
			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			for _, nn := range []string{"x", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			validateOrFailFunc("x", 80, policy, reachability, true)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector", map[string]string{"pod": "x"}, allowedNamespaces)
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
			for _, nn := range []string{"x", "z"} {
				for _, pp := range []string{"a", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			validateOrFailFunc("x", 80, policy, reachability, true)
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
				policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector", map[string]string{"pod": "x"}, allowedNamespaces)
				// Adding a namespace filter to a networkpolicy ingressRule will tighten the security boundary.
				// In this case, now ONLY y/b will be allowed.
				policy.Spec.Ingress[0].From[0].NamespaceSelector = &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "b",
					},
				}
				reachability := netpol.NewReachability(scenario.allPods, true)
				// disallow all traffic from the x or z namespaces.. but allow 'specifically' y/b.
				for _, nn := range []string{"x", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), pp == "b" && nn == "y")
					}
				}
				validateOrFailFunc("x", 80, policy, reachability, true)
			})

			ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
				ginkgo.By("Creating a network policy which only allows whitelisted namespaces (y) to connect on exactly one port (81)")
				allowedLabels := &metav1.LabelSelector{
					MatchLabels: map[string]string{"ns": "y"},
				}
				policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-81", map[string]string{"pod": "a"}, allowedLabels)

				// allow all traffic from the x,y,z namespaces
				reachability := netpol.NewReachability(scenario.allPods, true)

				// disallow all traffic from the x or z namespaces
				for _, nn := range []string{"x", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
					}
				}
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)

				policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
					Port: &intstr.IntOrString{IntVal: 81},
				}}

				// 1) Make sure now that port 81 works ok for the y namespace...
				validateOrFailFunc("x", 81, policy, reachability, false)

				// 2) Verify that port 80 doesnt work for any namespace (other then loopback)
				ginkgo.By("Verifying that all traffic to another port, 80, is blocked.")
				reachability = netpol.NewReachability(scenario.allPods, false)
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
				validateOrFailFunc("x", 80, policy, reachability, false)

				// 3) Verify that we can stack a policy to unblock port 80

				// Note that this final stacking test implements the
				// "should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]"
				// test specification, as it has already setup a set of policies which allowed some, but not all traffic.
				// Now we will add another policy for port 80, and verify that it is unblocked...
				ginkgo.By("Verifying that we can stack a policy to unblock port 80")
				policy2 := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels)
				policy2.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
					Port: &intstr.IntOrString{IntVal: 80},
				}}
				validateOrFailFunc("x", 80, policy, reachability, false)
			})

			ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
				ginkgo.By("Creating a network policy which allows all traffic.")
				policy := netpol.GetAllowAll("allow-all")
				ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
				reachability := netpol.NewReachability(scenario.allPods, true)
				validateOrFailFunc("x", 80, policy, reachability, true)
				validateOrFailFunc("x", 81, policy, reachability, false)
			})

			ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
				policy := netpol.GetAllowAll("allow-all-on-81")

				// Add a 'port' rule to the AllowAll ingress type, so now only 81 is valid.
				policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81"},
				}}

				// disallow all traffic from the x or z namespaces
				reachability := netpol.NewReachability(scenario.allPods, true)
				validateOrFailFunc("x", 81, policy, reachability, true)

				// disallow all traffic from the x or z namespaces
				reachability80 := netpol.NewReachability(scenario.allPods, false)
				reachability80.Expect("x/a", "x/a", true)
				validateOrFailFunc("x", 80, nil, reachability, false)

			})

			ginkgo.It("should allow ingress access from namespace on one named port [Feature:NetworkPolicy]", func() {
				allowedLabels := &metav1.LabelSelector{
					MatchLabels: map[string]string{"ns": "y"},
				}
				policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels)
				policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
				}}

				reachability := netpol.NewReachability(scenario.allPods, true)

				// disallow all traffic from the x or z namespaces
				for _, nn := range []string{"x", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability.Expect(netpol.NewPod(nn, pp), "x/a", false)
					}
				}

				validateOrFailFunc("x", 80, policy, reachability, false)

				// now validate 81 doesnt work, AT ALL, even for ns y... this validation might be overkill,
				// but still should be pretty fast.
				reachability = netpol.NewReachability(scenario.allPods, false)
				validateOrFailFunc("x", 81, policy, reachability, false)

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
				validateOrFailFunc("x", 80, policy, reachability, false)

				// meanwhile no traffic over 81 should work, since our egress policy is on 80
				reachability81 := netpol.NewReachability(scenario.allPods, false)
				for _, nn := range []string{"x", "y", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability81.Expect("x/a", netpol.NewPod(nn, pp), false)
					}
				}
				// no input policy, dont erase the last one...
				validateOrFailFunc("x", 81, nil, reachability81, false)
			})

			// The simplest possible mutation for this test - which is denyall->allow all.
			ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
				// part 1) allow all
				policy := netpol.GetAllowAll("allow-all-mutate-to-deny-all")
				reachability := netpol.NewReachability(scenario.allPods, true)
				validateOrFailFunc("x", 81, policy, reachability, false)

				// part 2) update the policy and confirm deny all
				policy = netpol.GetDefaultALLDenyPolicy("allow-all-mutate-to-deny-all")
				reachability = netpol.NewReachability(scenario.allPods, false)
				reachability.Expect("x/a", "x/a", true)
				reachability.Expect("x/b", "x/b", true)
				reachability.Expect("x/b", "x/b", true)

				validateOrFailFunc("x", 81, policy, reachability, false)

			})

			ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
				// add a new label, we'll remove it after this test is
				allowedLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"ns2": "updated"}}

				policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

				reachability := netpol.NewReachability(scenario.allPods, true)
				// disallow all traffic from the x or z namespaces
				for _, nn := range []string{"x", "y", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						// nobody can talk to a bc nothing has this ns2:updated label...
						reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
					}
				}
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
				validateOrFailFunc("x", 80, policy, reachability, true)

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
				validateOrFailFunc("x", 80, policy, reachability, false)

			})

			//  This function enables, and then denies, access to an updated pod. combining two previous test cases into
			//  one so as to reuse the same test harness.
			// 	so this implements ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
			//  as well.
			ginkgo.It("should allow ingress access from updated pod , and deny access to the updated pod as well [Feature:NetworkPolicy]", func() {
				// add a new label, we'll remove it after this test is
				allowedLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod2": "updated"}}

				policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

				// 1) Confirm that traffic is denied because the pod2:updated hasn't been applied to podB yet.
				// We'll apply that in step (2).
				reachability := netpol.NewReachability(scenario.allPods, true)
				// disallow all traffic from the x or z namespaces
				for _, nn := range []string{"x", "y", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						// nobody can talk to a bc nothing has this ns2:updated label...
						reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
					}
				}
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
				validateOrFailFunc("x", 80, policy, reachability, true)

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
				validateOrFailFunc("x", 80, nil, reachability, false)

				// (3) Now validate that denial is recovered from removing the label...
				// delete this label, so we can confirm that removing it DENIES access to the pod,
				// i.e. this is the 'should deny ingress access to updated pod' case.
				cleanNewLabel()

				reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/a"), false)
				validateOrFailFunc("x", 80, nil, reachability, false)
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

				validateOrFailFunc("x", 80, policy, reachability, true)

				// meanwhile no traffic over 81 should work, since our egress policy is on 80
				reachability81 := netpol.NewReachability(scenario.allPods, false)
				for _, nn := range []string{"x", "y", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability81.Expect("x/a", netpol.NewPod(nn, pp), false)
					}
				}
				// no input policy, dont erase the last one...
				validateOrFailFunc("x", 81, nil, reachability81, false)
			})

			ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
				policy := netpol.GetPolicyWithEgressRule("x", "a", "y", "c")

				reachability := netpol.NewReachability(scenario.allPods, true)
				for _, nn := range []string{"x", "y", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability.Expect("x/a", netpol.NewPod(nn, pp), false)
					}
				}
				reachability.Expect("x/a", "x/a", true)
				reachability.Expect("x/a", "y/c", true)

				validateOrFailFunc("x", 80, policy, reachability, true)

			})

			// new implementation : Akash
			ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
				ginkgo.By("Creating a network policy for the server which allows traffic only from client-b.")
				allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
				policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)

				reachability := netpol.NewReachability(scenario.allPods, true)
				reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
				reachability.ExpectAllIngress(netpol.PodString("x/b"), true)
				reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
				// allow loopback
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
				reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
				reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)

				validateOrFailFunc("x", 80, policy, reachability, true)

				policyAllowAllIngress := netpol.GetAllowAll("allow-all")
				ginkgo.By("Creating a network policy for the server which allows traffic from all clients.")
				reachability = netpol.NewReachability(scenario.allPods, true)
				validateOrFailFunc("x", 80, policyAllowAllIngress, reachability, false)
			})

			ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {
				policy := netpol.GetPolicyWithEgressRule("x", "a", "y", "c")

				reachability := netpol.NewReachability(scenario.allPods, true)
				for _, nn := range []string{"x", "y", "z"} {
					for _, pp := range []string{"a", "b", "c"} {
						reachability.Expect("x/a", netpol.NewPod(nn, pp), false)
					}
				}
				reachability.Expect("x/a", "x/a", true)
				reachability.Expect("x/a", "y/c", true)

				validateOrFailFunc("x", 80, policy, reachability, true)

				ginkgo.By("Creating a network policy which allows traffic to all pods.")
				policyEgressAllowAll := netpol.GetDefaultAllAllowEggress("allow-all-eggress")

				policyEgressAllowAll, err := f.ClientSet.NetworkingV1().NetworkPolicies(f.Namespace.Name).Create(context.TODO(), policyEgressAllowAll, metav1.CreateOptions{})
				if err != nil {
					panic("ffffff")
				}
				ginkgo.By("Creating a network policy for the server which allows traffic from all clients.")
				reachability = netpol.NewReachability(scenario.allPods, true)
				validateOrFailFunc("x", 80, policyEgressAllowAll, reachability, false)
			})

			ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {

				ginkgo.By("Creating a network policy for the server which denies all traffic.")
				policy := netpol.GetDefaultALLDenyPolicy("deny-all")
				reachability := netpol.NewReachability(scenario.allPods, false)

				// allow loopback
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
				reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
				reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)

				validateOrFailFunc("x", 80, policy, reachability, true)

				ginkgo.By("Creating a network policy for the server which allows traffic only from pod b.")

				allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
				updatedPolicy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)

				reachability = netpol.NewReachability(scenario.allPods, true)
				reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
				reachability.ExpectAllIngress(netpol.PodString("x/b"), true)
				reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
				// allow loopback
				reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)
				reachability.Expect(netpol.PodString("x/b"), netpol.PodString("x/b"), true)
				reachability.Expect(netpol.PodString("x/c"), netpol.PodString("x/c"), true)
				validateOrFailFunc("x", 80, updatedPolicy, reachability, true)
			})
		})
	})
})
