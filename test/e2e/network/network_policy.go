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
	"time"

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
	pods       []string
	namespaces []string
	p80        int
	p81        int
	allPods    []netpol.PodString
	podIPs     map[string]string
}

// forEach is a convenient function for iterating through all combinations
// of to->from pods in the scenario.
func (s *Scenario) forEach(process func(netpol.PodString, netpol.PodString)) {
	for _, n := range s.namespaces {
		for _, p := range s.pods {
			for _, nn := range s.namespaces {
				for _, pp := range s.pods {
					process(netpol.PodString(n+"/"+p), netpol.PodString(nn+"/"+pp))
				}
			}
		}
	}
}

// NewScenario creates a new test scenario.
func NewScenario() *Scenario {
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

func log(s string){
	fmt.Println(s)
}

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
				k8s.CleanNetworkPolicies([]string{"x", "y", "z"})

				// convenience: putting unit tests in here for now...
				if netpol.PodString("x/a") != netpol.NewPod("x", "a") {
					panic("omg theyre not the same, dying")
				}
			}
		}()
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.AfterEach(func() {
			// delete all network policies in namespaces x, y, z
		})

		cleanup := func() {
			k8s.CleanNetworkPolicies([]string{"x", "y", "z"})
		}

		validateOrFailFunc := func(ns string, fromPort, toPort int,  policy *networkingv1.NetworkPolicy, reachability *netpol.Reachability, cleanPreviousPolicies bool) {
			if cleanPreviousPolicies == true {
				cleanup()
			}

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
			ginkgo.By("Validating reachability matrix...")

			netpol.Validate(k8s, reachability, fromPort, toPort)
			fmt.Println("VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV")

			reachability.PrintSummary(true, true, true)

			if _, wrong, _ := reachability.Summary(); wrong != 0 {
				ginkgo.Fail("Had more then one wrong result in the reachability matrix.")
			} else {
				fmt.Println("VALIDATION SUCCESSFUL............................................................")
			}
			fmt.Println("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")

		}

		ginkgo.It("im not crazy", func() {
			time.Sleep(5*time.Second)
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			// 			podList, err := clientset.Core().Pods(name).List(api.ListOptions{LabelSelector: set.AsSelector()})
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			if err != nil {
				panic(err)
			}
			pod := podList.Items[0]
			fmt.Print(fmt.Sprintf("\n\npod:::::%v\n\n",pod.Status.PodIP))


		})

		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDefaultDenyIngressPolicy("deny-ingress")

			reachability := netpol.NewReachability(scenario.allPods, true)

			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)
		})

		ginkgo.It("should support a 'default-deny-all' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDefaultALLDenyPolicy("deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllEgress(netpol.PodString("x/b"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			reachability.ExpectAllEgress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability.ExpectAllEgress(netpol.PodString("x/c"), false)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)
			// TODO, should we have a positive control before this test runs in GinkoEach?
		})

		// The next two tests test an identical condition.
		// should enforce policy to allow traffic from pods within server namespace based on PodSelector
		// should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]
		ginkgo.It("should enforce policy that allows only a specific pod in the same namespace (based on PodSelector) [Feature:NetworkPolicy]", func() {

			// We will reuse this scenario in both validations...

			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to == "x/a" && from != "x/b" {
					reachability.Expect(from, to, false)
				}
			})
			reachability.AllowLoopback()

			ginkgo.By("Using a LABEL SELECTOR")

			policy := netpol.GetAllowBasedOnPodSelector("x-a-allows-x-b", map[string]string{"pod": "a"}, &metav1.LabelSelector{
				MatchLabels: map[string]string{"pod": "b"},
			})
			validateOrFailFunc("x", 82,80, policy, reachability, true)

			ginkgo.By("Using a MATCH EXPRESSION")

			policy2 := netpol.GetAllowBasedOnPodSelector("x-a-allows-x-b", map[string]string{"pod": "a"}, &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			})

			validateOrFailFunc("x", 82,80, policy2, reachability, true)
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

			validateOrFailFunc("x", 82,80, policy, reachability, true)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector", map[string]string{"pod": "a"}, allowedNamespaces)
			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			for _, nn := range []string{"x", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)
		})

		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector", map[string]string{"pod": "a"}, allowedNamespaces)

			podBWhitelisting := networkingv1.NetworkPolicyPeer{
				PodSelector: &metav1.LabelSelector{
					MatchLabels: map[string]string{
						"pod": "b",
					},
				},
			}
			/**
			 * Here we add a second Ingress rule, such that our overall ingress will look like this...
			 * - From:
			 * - From:
			 */
			policy.Spec.Ingress = append(policy.Spec.Ingress, networkingv1.NetworkPolicyIngressRule{From: []networkingv1.NetworkPolicyPeer{
				podBWhitelisting,
			}})

			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.Expect("x/a", "x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.Expect("x/c", "x/a", false)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)

		})

		// TODO We probably should have a test for multiple ns and pod filters.

		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-matchselector2", map[string]string{"pod": "a"}, allowedNamespaces)

			/**
			 * Here we add a PodSelector to the SAME rule that we made above.
			 * Making this much more selective then the previous 'or' test.
			 */
			policy.Spec.Ingress[0].From[0].PodSelector = &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}

			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to == "x/a"{
					if from.Namespace() == "z" || from.Namespace() == "y" {
						if from.PodName() != "b" {
							reachability.Expect(from, to, false)
						}
					}
					if from.Namespace() == "x" {
						reachability.Expect(from, to, false)
					}
				}
			})
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)
		})

		// This tests both verifies stacking as well as ports.
		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ginkgo.By("*************** Creating a network policy which only allows whitelisted namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{"ns": "y"},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			// allow all traffic from the x,y,z namespaces
			reachabilityALLOW := netpol.NewReachability(scenario.allPods, true)

			scenario.forEach(func(from netpol.PodString, to netpol.PodString){
				if to=="x/a" {
					if from.Namespace()=="y"{
						reachabilityALLOW.Expect(from, to,true )
					}
					if from.Namespace()=="z"{
						reachabilityALLOW.Expect(from, to ,false )
					}
					if from.Namespace()=="x"{
						reachabilityALLOW.Expect(from, to,false )
					}
				}
			})
			reachabilityALLOW.AllowLoopback()

			policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{
					IntVal: 81,
				},
			}}

			// 1) Make sure now that port 81 works ok for the y namespace THEN 2) Verify that port 80 doesnt work for any namespace (other then loopback)

			ginkgo.By("************* Verifying that all traffic to another port, 81, is works.")
			validateOrFailFunc("x", 82,81, policy, reachabilityALLOW, true)
			ginkgo.By("************ Verifying that all traffic to another port, 80, is blocked.")
			reachabilityDENY := netpol.NewReachability(scenario.allPods, true)
			reachabilityDENY.ExpectAllIngress("x/a",false)
			reachabilityDENY.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachabilityDENY, false)

			// 3) Verify that we can stack a policy to unblock port 80

			// Note that this final stacking test implements the
			// "should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]"
			// test specification, as it has already setup a set of policies which allowed some, but not all traffic.
			// Now we will add another policy for port 80, and verify that it is unblocked...
			ginkgo.By("************ Verifying that we can stack a policy to unblock port 80")
			policy2 := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels)
			policy2.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{IntVal: 80},
			}}
			validateOrFailFunc("x", 82,80, policy2, reachabilityALLOW, false)
		})

		ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			policy := netpol.GetAllowAll("allow-all")
			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 82,80, policy, reachability, true)
			validateOrFailFunc("x", 82,81, policy, reachability, false)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowAll("allow-all")

			// WARNING ! Since we are adding a port rule, that means that the lack of a
			// pod selector will cause this policy to target the ENTIRE namespace.....
			ginkgo.By("Blocking all ports other then 81 in the entire namespace")
			policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81"},
			}}

			// disallow all traffic from the x or z namespaces
			reachability := netpol.NewReachability(scenario.allPods, true)

			validateOrFailFunc("x",82, 81, policy, reachability, true)

			// disallow all traffic from the x or z namespaces
			reachability80 := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to.Namespace() == "x" {
					reachability80.Expect(from, to, false)
				}
			})
			reachability80.AllowLoopback()
			validateOrFailFunc("x", 82,80, nil, reachability80, false)
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
			reachability.AllowLoopback()

			validateOrFailFunc("x",82, 80, policy, reachability, false)

			// now validate 81 doesnt work, AT ALL, even for ns y... this validation might be overkill,
			// but still should be pretty fast.
			reachabilityFAIL := netpol.NewReachability(scenario.allPods, true)
			reachabilityFAIL.ExpectAllIngress("x/a",false)
			reachabilityFAIL.AllowLoopback()
			cleanup()
			validateOrFailFunc("x", 82,81, policy, reachabilityFAIL, true)
		})

		// TODO In this test we remove the DNS check.  Write a higher level DNS checking test
		// which can be used to fulfill that requirement.
		ginkgo.It("should allow egress access on one named port [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowAll("allow-egress")
			// By adding a port rule to the egress class we now restrict regress to only work on
			// port 80.  We add DNS support as well so that this can be done over a service.
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{},
							// allow all
							NamespaceSelector: &metav1.LabelSelector{},
							IPBlock: nil,
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
						},
					},
				},
			}
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 82,80, policy, reachability, true)

			// meanwhile no traffic over 81 should work, since our egress policy is on 82
			reachability81 := netpol.NewReachability(scenario.allPods, true)
			reachability81.ExpectAllEgress("x/a", false)
			reachability81.ExpectAllEgress("x/b", false)
			reachability81.ExpectAllEgress("x/c", false)
			reachability81.AllowLoopback()
			// no input policy, dont erase the last one...
			validateOrFailFunc("x", 82,81, nil, reachability81, false)
		})


		// The simplest possible mutation for this test - which is denyall->allow all.
		ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
			// part 1) allow all
			policy := netpol.GetAllowAll("allow-all-mutate-to-deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x",82, 81, policy, reachability, true)

			// part 2) update the policy to deny all, empty...
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			reachability = netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to.Namespace() == "x" {
					reachability.Expect(from, to, false)
				}
			})
			reachability.AllowLoopback()
			validateOrFailFunc("x",82, 81, policy, reachability, false)
		})

		// WEDNESDAY

		ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
			// add a new label, we'll remove it after this test is completed...
			cleanNewLabel := func() {
				nsY, _ := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), "y", metav1.GetOptions{})
				nsY.ObjectMeta.Labels=map[string]string{"ns":"y"}
				_,_ = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), nsY, metav1.UpdateOptions{})
			}
			cleanNewLabel() // in case its dirty, clean before this test starts... TODO replace w/ global ns cleaner.
			defer cleanNewLabel()

			AddNewLabel := func() {
				nsY, _ := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), "y", metav1.GetOptions{})
				nsY.ObjectMeta.Labels["ns2"]="updated"
				nsY.ObjectMeta.Labels["ns"]="y"
				_,_ = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), nsY, metav1.UpdateOptions{})
			}

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
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)
			
			AddNewLabel()


			// now update our matrix - we want anything 'y' to be able to get to x/a...
			reachability.Expect(netpol.PodString("y/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("y/b"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("y/c"), netpol.PodString("x/a"), true)
			validateOrFailFunc("x",82, 80, policy, reachability, false)
		})

		//  This function enables, and then denies, access to an updated pod. combining two previous test cases into
		//  one so as to reuse the same test harness.
		// 	so this implements ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
		//  as well.
		ginkgo.It("should allow ingress access from updated pod , and deny access to the updated pod as well [Feature:NetworkPolicy]", func() {
			// add a new label, we'll remove it after this test is
			allowedLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod":"b", "pod2": "updated"}}

			xb, err := f.ClientSet.AppsV1().Deployments("x").Get(context.TODO(), "xb", metav1.GetOptions{})

			reachability := netpol.NewReachability(scenario.allPods, true)

			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			validateUnreachable := func() {
				reachability.ExpectAllIngress("x/a", false)
				reachability.AllowLoopback()
				validateOrFailFunc("x", 82, 80, policy, reachability, true)
			}

			cleanNewLabel := func() {
				xb, err = f.ClientSet.AppsV1().Deployments("x").Get(context.TODO(), "xb", metav1.GetOptions{})
				xb.Spec.Template.ObjectMeta.Labels=map[string]string{"pod":"b"}

				_, err = f.ClientSet.AppsV1().Deployments("x").Update(context.TODO(), xb, metav1.UpdateOptions{})
				if err != nil {
						log("possible problem ")
					panic(err)
				}
				time.Sleep(10*time.Second)
			}
			updateNewLabel := func() {
				xb, err = f.ClientSet.AppsV1().Deployments("x").Get(context.TODO(), "xb", metav1.GetOptions{})
				xb.Spec.Template.ObjectMeta.Labels=map[string]string{"pod":"b", "pod2":"updated"}
				_, err = f.ClientSet.AppsV1().Deployments("x").Update(context.TODO(), xb, metav1.UpdateOptions{})
				if err != nil {
					panic(err)
				}
				xb, err = f.ClientSet.AppsV1().Deployments("x").Get(context.TODO(), "xb", metav1.GetOptions{})
				if err != nil {
					panic(err)
				}
				fmt.Println(fmt.Sprintf("---> xb labels ----> %v", xb.ObjectMeta.Labels))
				time.Sleep(10*time.Second)
			}

			// replace this w/ a clean step in each that relabels ? seems like bespoke logic which we could use
			// in all tests...
			cleanNewLabel()

			validateUnreachable()

			updateNewLabel()

			ginkgo.By("Verfying it works nowwwwwwwwwwww")
			reachability.Expect("x/b", "x/a", true )
			validateOrFailFunc("x", 82,80, nil, reachability, false)

			ginkgo.By("final removal of label to confir blacklisting is back")
			cleanNewLabel()
			validateUnreachable()
		})

		// ingress NS + PORT
		// egress NS + PORT
		ginkgo.It("should work with Ingress, Egress specified together [Feature:NetworkPolicy]", func() {


			allowedPodLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b"}}
			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-pod-selector", map[string]string{"pod": "a"}, allowedPodLabels)
			// add an egress rule on to it... 
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
			reachability.ExpectAllIngress("x/a",false)
			reachability.Expect("x/b","x/a",true)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82,80, policy, reachability, true)

			ginkgo.By("validating that 81 doesnt work.......................................")

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachability.ExpectAllEgress("x/a",false)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82, 81, nil, reachability, false)

		})

		ginkgo.It("should enforce multiple egress policies with egress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {


			policy := netpol.GetDefaultAllAllowEggress("allow-all")
			// add an egress rule on to it... 
			policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
						},
					},
				},
			}

			ginkgo.By("making sure egress doesnt work to start")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllEgress("x/a",false)
			reachability.ExpectAllEgress("x/b",false)
			reachability.ExpectAllEgress("x/c",false)
			reachability.AllowLoopback()
			validateOrFailFunc("x", 82, 81, policy, reachability, false)

			ginkgo.By("FIXING IT !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
			// 2nd allow all policy, we wont mess it up this time thought.
			reachability.ExpectAllEgress("x/a",true)
			reachability.ExpectAllEgress("x/b",true)
			reachability.ExpectAllEgress("x/c",true)

			policy2 := netpol.GetDefaultAllAllowEggress("allow-all-2")
			validateOrFailFunc("x", 82, 81, policy2, reachability, false)

		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {

			ginkgo.By("Creating a network policy for the server which denies all traffic.")
			policy := netpol.GetDefaultALLDenyPolicy("deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.AllowLoopback()
			scenario.forEach(func(from, to netpol.PodString) {
				if from.Namespace()=="x" || to.Namespace()=="x" {
					if from != to {
						reachability.Expect(from, to, false)
					}
				}
			})
			validateOrFailFunc("x",82,80,policy,reachability, true)

			err := k8s.CleanNetworkPolicies([]string{"x", "y", "z"})
			time.Sleep(1*time.Second)
			if err != nil {
				ginkgo.Fail(fmt.Sprintf("%v",err))
			}
			reachability = netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 82, 80, nil, reachability, false)
		})

		ginkgo.It("should enforce policies to check ingress and egress policies can be controlled independently based on PodSelector [Feature:NetworkPolicy]", func() {
			/*
				Test steps:
				1. Verify every pod in every namespace can talk to each other
				2. Create and apply a policy to allow eggress traffic to pod b
				3. Deny all Ingress traffic to Pod A in Namespace A (so that B cannot talk to A, that is how it was originally
				4. Verify B cannot send traffic to A
				5. Verify A can send traffic to B
			*/
			policy := netpol.GetAllowAll("allow-all")

			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc("x", 82, 80, policy, reachability, true)

			ginkgo.By("Creating a network policy for pod-a which allows Egress traffic to pod-b.")

			egressPolicyAllowToB := netpol.GetPolicyWithEgressRuleOnlyPodSelector("x", "a", "b")

			reachability = netpol.NewReachability(scenario.allPods, true)
			for _,nn := range []string{"x","y","z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect("x/a",netpol.NewPod(nn,pp), false)
				}
			}
			reachability.Expect("x/a","x/a", true)
			reachability.Expect("x/a","x/b", true)

			validateOrFailFunc("x", 82, 80, egressPolicyAllowToB, reachability,true)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")
			policyDenyFromPodB := netpol.GetDefaultDenyIngressPolicy("deny-all")

			reachability2 := netpol.NewReachability(scenario.allPods, true)

			reachability2.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability2.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability2.ExpectAllIngress(netpol.PodString("x/c"), false)
			reachability2.AllowLoopback()
			validateOrFailFunc("x", 82,80, policyDenyFromPodB, reachability2, true)
		})
	})
})
