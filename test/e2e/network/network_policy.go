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
	"github.com/onsi/ginkgo"
	"time"

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

func validateOrFailFunc (k8s *netpol.Kubernetes, f *framework.Framework, ns string, fromPort, toPort int, policy *networkingv1.NetworkPolicy,
	reachability *netpol.Reachability, cleanPreviousPolicies bool, scenario *Scenario) {
	if cleanPreviousPolicies == true {
		err := k8s.CleanNetworkPolicies(scenario.namespaces)
		framework.ExpectNoError(err, "Error occurred while cleaning network policy")

	}

	if policy != nil {
		fmt.Println("Network Policy creating ", policy.Name)
		_, err1 := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Create(context.TODO(), policy, metav1.CreateOptions{})
		if err1 != nil {
			fmt.Println("Network Policy failed to create, trying to update... ", policy.Name)
			_, err2 := f.ClientSet.NetworkingV1().NetworkPolicies(ns).Update(context.TODO(), policy, metav1.UpdateOptions{})
			if err2 != nil {
				framework.Failf("Network Policy failed CREATING and UPDATING .... %v .... %v", err1, err2)
			}
		}
	}
	ginkgo.By("Validating reachability matrix...")

	netpol.Validate(k8s, reachability, fromPort, toPort)

	reachability.PrintSummary(true, true, true)

	if _, wrong, _ := reachability.Summary(); wrong != 0 {
		framework.Failf("Had more then one wrong result in the reachability matrix.\n")
	} else {
		fmt.Println("VALIDATION SUCCESSFUL")
	}

}

func nsLabelCleaner(f *framework.Framework, ns string){
	selectedNameSpace, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get namespace %v", ns)
	selectedNameSpace.ObjectMeta.Labels = map[string]string{"ns": ns}
	_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update Namespace %v", ns)
	time.Sleep(10 * time.Second)
}

func podLabelCleaner(f *framework.Framework, ns string, pod string) {
	selectedPod, err := f.ClientSet.AppsV1().Deployments(ns).Get(context.TODO(), ns+pod, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get pod %v in namespace %v", pod, ns)
	selectedPod.Spec.Template.ObjectMeta.Labels = map[string]string{"pod": pod}
	_, err = f.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), selectedPod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update pod %v labels in namespace %v", pod, ns)
	time.Sleep(10 * time.Second)

}

func nsLabelUpdater(f *framework.Framework, ns string, newNsLabel map[string]string) {
	selectedNameSpace, err := f.ClientSet.CoreV1().Namespaces().Get(context.TODO(), ns, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get namespace %v", ns)
	selectedNameSpace.ObjectMeta.Labels = newNsLabel
	_, err = f.ClientSet.CoreV1().Namespaces().Update(context.TODO(), selectedNameSpace, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update Label of namespace %v", ns)
	time.Sleep(10 * time.Second)
}

func podLabelUpdater(f *framework.Framework, ns string, pod string, newPodLabel map[string]string) {
	selectedPod, err := f.ClientSet.AppsV1().Deployments(ns).Get(context.TODO(), ns+pod, metav1.GetOptions{})
	framework.ExpectNoError(err, "Failing to get pod %v in namespace %v", pod, ns)
	selectedPod.Spec.Template.ObjectMeta.Labels = newPodLabel
	_, err = f.ClientSet.AppsV1().Deployments(ns).Update(context.TODO(), selectedPod, metav1.UpdateOptions{})
	framework.ExpectNoError(err, "Failing to update pod %v labels in namespace %v", pod, ns)
	time.Sleep(10 * time.Second)

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

func log(s string) {
	fmt.Println(s)
}

var _ = SIGDescribe("NetworkPolicy [LinuxOnly]", func() {
	f := framework.NewDefaultFramework("network-policy")

	var k8s *netpol.Kubernetes
	var scenario *Scenario
	var reachability *netpol.Reachability
	ginkgo.BeforeEach(func() {
		func() {
			scenario = NewScenario()
			if k8s == nil {
				k8s, _ = netpol.NewKubernetes()
				k8s.Bootstrap()
				//TODO Adding the following line will show the error thus cause the failure. Discuss why
				//framework.ExpectNoError(err, "Error occurs when bootstraping k8s")

				//TODO move to different location for unit test
				if netpol.PodString("x/a") != netpol.NewPod("x", "a") {
					framework.Failf("Namespace, pod representation doesn't match PodString type")
				}
			}
		}()
	})

	ginkgo.Context("NetworkPolicy between server and client", func() {
		ginkgo.BeforeEach(func() {
			ginkgo.By("Testing pods can connect to both ports when no policy is present.")
			//test positive flow
			err := k8s.CleanNetworkPolicies(scenario.namespaces)
			framework.ExpectNoError(err, "Error occurred while cleaning network policy")
			reachability = netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc(k8s,f, "x", 82, 80, nil, reachability, false, scenario)
		})


		ginkgo.It("should support a 'default-deny-ingress' policy [Feature:NetworkPolicy]", func() {
			policy := netpol.GetDefaultDenyIngressPolicy("deny-ingress")

			reachability = netpol.NewReachability(scenario.allPods, true)

			reachability.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability.ExpectAllIngress(netpol.PodString("x/c"), false)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)
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
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)
		})

		// The next two tests test an identical condition.
		// should enforce policy to allow traffic from pods within server namespace based on PodSelector
		// should enforce policy based on PodSelector with MatchExpressions[Feature:NetworkPolicy]
		ginkgo.It("should enforce policy that allows only a specific pod in the same namespace (based on PodSelector) [Feature:NetworkPolicy]", func() {

			// We will reuse this scenario in both validations...
			ginkgo.By("Using a LABEL SELECTOR")
			allowedPods := metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}

			policy := netpol.GetAllowBasedOnPodSelector("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)


			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to == "x/a" && from != "x/b" {
					reachability.Expect(from, to, false)
				}
			})
			reachability.AllowLoopback()

			validateOrFailFunc(k8s, f,"x", 82, 80, policy, reachability, true, scenario)

			ginkgo.By("Using a MATCH EXPRESSION")

			allowedPods = metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b"},
				}},
			}
			policy2 := netpol.GetAllowBasedOnPodSelector("x-a-allows-x-b", map[string]string{"pod": "a"}, &allowedPods)

			validateOrFailFunc(k8s, f, "x", 82, 80, policy2, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy to allow traffic only from a different namespace, based on NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.allPods, true)

			// disallow all traffic from the x or z namespaces
			for _, nn := range []string{"x", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.Expect(netpol.PodString("x/a"), netpol.PodString("x/a"), true)

			// TODO Discuss if this is a better way of constructing reachability
			//scenario.forEach(func(from, to netpol.PodString) {
			//	if to == "x/a" {
			//		if from.Namespace() == "z" || from.Namespace() == "x" {
			//			reachability.Expect(from, to, false)
			//		}
			//	}
			//})
			//reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy based on NamespaceSelector with MatchExpressions[Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"y"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces)
			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			// TODO same as above, discuss if using foreach func is a better way of constructing reachability
			for _, nn := range []string{"x", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)
		})

		// TODO should we create a new function which can take multiple ingress rule.
		ginkgo.It("should enforce policy based on PodSelector or NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-match-selector", map[string]string{"pod": "a"}, allowedNamespaces)

			podBAllowlisting := networkingv1.NetworkPolicyPeer{
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
				podBAllowlisting,
			}})

			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.Expect("x/a", "x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.Expect("x/c", "x/a", false)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)

		})


		ginkgo.It("should enforce policy based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-podselector-and-nsselector", map[string]string{"pod": "a"}, allowedNamespaces)

			/**
			 * Here we add a PodSelector to the SAME rule that we made above.
			 * Making this much more selective then the previous 'or' test.
			 */
			allowedPod := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": "b",
				},
			}
			policy.Spec.Ingress[0].From[0].PodSelector = allowedPod

			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to == "x/a" {
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
			validateOrFailFunc(k8s, f,"x", 82, 80, policy, reachability, false, scenario)
		})

		//add this new case to allow multiple podselctor and namespaceselectors
		ginkgo.It("should enforce policy based on Multiple PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func() {
			allowedNamespaces := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "ns",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{"x"},
				}},
			}

			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-ns-y-z-pod-b-c", map[string]string{"pod": "a"}, allowedNamespaces)

			/**
			 * Here we add a PodSelector to the SAME rule that we made above.
			 * Making this much more selective then the previous 'or' test.
			 */
			allowedPod := &metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "pod",
					Operator: metav1.LabelSelectorOpIn,
					Values:   []string{"b", "c"},
				}},
			}
			policy.Spec.Ingress[0].From[0].PodSelector = allowedPod


			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to == "x/a" {
					if from.Namespace() == "z" || from.Namespace() == "y" {
						if from.PodName() == "a" {
							reachability.Expect(from, to, false)
						}
					}
					if from.Namespace() == "x" {
						reachability.Expect(from, to, false)
					}
				}
			})
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f,"x", 82, 80, policy, reachability, false, scenario)
		})

		ginkgo.It("should enforce policy to allow traffic only from a pod in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func(){
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

			policy := netpol.GetAllowBasedOnPodSelectorandNamespaceSelectorFromOtherNamespace("x", "allow-ns-y-pod-a-via-namespace-pod-selector",
				map[string]string{"pod" : "a"}, allowedNamespaces, allowedPods)

			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to == "x/a" {
					if from != "y/a" {
						reachability.Expect(from, to, false)
					}
				}
			})
			reachability.AllowLoopback()

			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)

		})

		// This tests both verifies stacking as well as ports.
		ginkgo.It("should enforce policy based on Ports [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which only allows allowlisted namespaces (y) to connect on exactly one port (81)")
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
			}
			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			// allow all traffic from the x,y,z namespaces
			reachabilityALLOW := netpol.NewReachability(scenario.allPods, true)

			scenario.forEach(func(from netpol.PodString, to netpol.PodString) {
				if to == "x/a" {
					if from.Namespace() == "y" {
						reachabilityALLOW.Expect(from, to, true)
					}
					if from.Namespace() == "z" {
						reachabilityALLOW.Expect(from, to, false)
					}
					if from.Namespace() == "x" {
						reachabilityALLOW.Expect(from, to, false)
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

			ginkgo.By("Verifying that all traffic to another port, 81, is works.")
			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachabilityALLOW, true, scenario)
			ginkgo.By("Verifying that all traffic to another port, 80, is blocked.")
			reachabilityDENY := netpol.NewReachability(scenario.allPods, true)
			reachabilityDENY.ExpectAllIngress("x/a", false)
			reachabilityDENY.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachabilityDENY, false, scenario)

			// 3) Verify that we can stack a policy to unblock port 80

			// Note that this final stacking test implements the
			// "should enforce multiple, stacked policies with overlapping podSelectors [Feature:NetworkPolicy]"
			// test specification, as it has already setup a set of policies which allowed some, but not all traffic.
			// Now we will add another policy for port 80, and verify that it is unblocked...
			ginkgo.By("Verifying that we can stack a policy to unblock port 80")
			policy2 := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector-80", map[string]string{"pod": "a"}, allowedLabels)
			// TODO instead of creating a new policy can we stack the old policy to unblock 80
			policy2.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{IntVal: 80},
			}}
			validateOrFailFunc(k8s, f, "x", 82, 80, policy2, reachabilityALLOW, false, scenario)
		})

		ginkgo.It("should support allow-all policy [Feature:NetworkPolicy]", func() {
			ginkgo.By("Creating a network policy which allows all traffic.")
			policy := netpol.GetAllowAll("allow-all")
			ginkgo.By("Testing pods can connect to both ports when an 'allow-all' policy is present.")
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)
			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachability, false, scenario)
		})

		ginkgo.It("should allow ingress access on one named port [Feature:NetworkPolicy]", func() {
			policy := netpol.GetAllowAll("allow-all")

			// WARNING ! Since we are adding a port rule, that means that the lack of a
			// pod selector will cause this policy to target the ENTIRE namespace.....
			ginkgo.By("Blocking all ports other then 81 in the entire namespace")
			policy.Spec.Ingress[0].Ports = []networkingv1.NetworkPolicyPort{{
				Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-81"},
			}}

			reachability := netpol.NewReachability(scenario.allPods, true)

			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachability, true, scenario)

			// disallow all traffic from the x or z namespaces
			reachabilityPort80 := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to.Namespace() == "x" {
					reachabilityPort80.Expect(from, to, false)
				}
			})
			reachabilityPort80.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, nil, reachabilityPort80, false, scenario)
		})

		ginkgo.It("should allow ingress access from namespace on one named port [Feature:NetworkPolicy]", func() {
			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns": "y",
				},
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

			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)

			// now validate 81 doesnt work, AT ALL, even for ns y... this validation might be overkill,
			// but still should be pretty fast.
			reachabilityFAIL := netpol.NewReachability(scenario.allPods, true)
			reachabilityFAIL.ExpectAllIngress("x/a", false)
			reachabilityFAIL.AllowLoopback()
			//change here
			//k8s.CleanNetworkPolicies(scenario.namespaces)
			validateOrFailFunc(k8s, f,"x", 82, 81, policy, reachabilityFAIL, false, scenario)
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
							IPBlock:           nil,
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
			validateOrFailFunc(k8s, f,"x", 82, 80, policy, reachability, true, scenario)

			// meanwhile no traffic over 81 should work, since our egress policy is on 82
			reachability81 := netpol.NewReachability(scenario.allPods, true)
			reachability81.ExpectAllEgress("x/a", false)
			reachability81.ExpectAllEgress("x/b", false)
			reachability81.ExpectAllEgress("x/c", false)
			reachability81.AllowLoopback()
			// no input policy, dont erase the last one...
			validateOrFailFunc(k8s, f, "x", 82, 81, nil, reachability81, false, scenario)
		})

		// The simplest possible mutation for this test - which is allow all->deny all.
		ginkgo.It("should enforce updated policy [Feature:NetworkPolicy]", func() {
			// part 1) allow all
			policy := netpol.GetAllowAll("allow-all-mutate-to-deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachability, true, scenario)

			// part 2) update the policy to deny all, empty...
			policy.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{}
			reachability = netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if to.Namespace() == "x" {
					reachability.Expect(from, to, false)
				}
			})
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachability, false, scenario)
		})



		ginkgo.It("should allow ingress access from updated namespace [Feature:NetworkPolicy]", func() {
			nsLabelCleaner(f, "y")
			defer nsLabelCleaner(f, "y")
			// add a new label, we'll remove it after this test is completed...
			updatedLabels := map[string]string{
				"ns": "y",
				"ns2": "updated",
			}

			allowedLabels := &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"ns2": "updated",
				}}

			policy := netpol.GetAllowBasedOnNamespaceSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			reachability := netpol.NewReachability(scenario.allPods, true)
			// disallow all traffic from the x or z namespaces
			// TODO maybe use foreach function?
			for _, nn := range []string{"x", "y", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					// nobody can talk to a bc nothing has this ns2:updated label...
					reachability.Expect(netpol.PodString(nn+"/"+pp), netpol.PodString("x/a"), false)
				}
			}
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)

			nsLabelUpdater(f, "y", updatedLabels)

			// now update our matrix - we want anything 'y' to be able to get to x/a...
			reachability.Expect(netpol.PodString("y/a"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("y/b"), netpol.PodString("x/a"), true)
			reachability.Expect(netpol.PodString("y/c"), netpol.PodString("x/a"), true)
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, false, scenario)
		})

		//  This function enables, and then denies, access to an updated pod. combining two previous test cases into
		//  one so as to reuse the same test harness.
		// 	so this implements ginkgo.It("should deny ingress access to updated pod [Feature:NetworkPolicy]", func() {
		//  as well.
		ginkgo.It("should allow ingress access from updated pod , and deny access to the updated pod as well [Feature:NetworkPolicy]", func() {
			// add a new label, we'll remove it after this test is
			allowedLabels := &metav1.LabelSelector{MatchLabels: map[string]string{"pod": "b", "pod2": "updated"}}

			reachability := netpol.NewReachability(scenario.allPods, true)

			policy := netpol.GetAllowBasedOnPodSelector("allow-client-a-via-ns-selector", map[string]string{"pod": "a"}, allowedLabels)

			validateUnreachable := func() {
				reachability.ExpectAllIngress("x/a", false)
				reachability.AllowLoopback()
				validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)
			}



			podLabelCleaner(f, "x", "b")

			validateUnreachable()

			// now update label in x namespace and pod b
			updatedLabels := map[string]string{
				"pod": "b",
				"pod2": "updated",
			}
			podLabelUpdater(f, "x", "b", updatedLabels)

			ginkgo.By("There is connection between x/b to x/a when label is updated")
			reachability.Expect("x/b", "x/a", true)
			validateOrFailFunc(k8s, f, "x", 82, 80, nil, reachability, false, scenario)

			ginkgo.By("No connection when pod label has been updated to default")
			podLabelCleaner(f, "x", "b")
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
			reachability.ExpectAllIngress("x/a", false)
			reachability.Expect("x/b", "x/a", true)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)

			ginkgo.By("validating that port 81 doesn't work")

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachability.ExpectAllEgress("x/a", false)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 81, nil, reachability, false, scenario)

		})

		ginkgo.It("should enforce egress policy allowing traffic to a server in a different namespace based on PodSelector and NamespaceSelector [Feature:NetworkPolicy]", func () {
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
			policy := netpol.GetPolicyWithEgressrule("x", "allow-to-ns-y-pod-a", map[string]string{"pod":"a"}, allowedNamespaces, allowedPods)
			policy.Spec.Egress[0].Ports = []networkingv1.NetworkPolicyPort{
				{
					Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
				},
			}
			reachability := netpol.NewReachability(scenario.allPods, true)
			scenario.forEach(func(from, to netpol.PodString) {
				if from == "x/a" {
					if to != "y/a" {
						reachability.Expect(from, to, false)
					}
				}
			})
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)

			// meanwhile no traffic over 81 should work, since our egress policy is on 80
			reachability.ExpectAllEgress("x/a", false)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 81, nil, reachability, false, scenario)

		})

		ginkgo.It("should enforce multiple ingress policies with ingress allow-all policy taking precedence [Feature:NetworkPolicy]", func() {

			policyAllowOnlyPort80 := netpol.GetAllowAll("allow-all")
			policyAllowOnlyPort80.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{
							Port: &intstr.IntOrString{Type: intstr.String, StrVal: "serve-80"},
						},
					},
				},
			}

			ginkgo.By("Making sure ingress doesn't work other than port 80")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress("x/a", false)
			reachability.ExpectAllIngress("x/b", false)
			reachability.ExpectAllIngress("x/c", false)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 81, policyAllowOnlyPort80, reachability, true, scenario)

			ginkgo.By("Allowing all ports")
			reachability.ExpectAllIngress("x/a", true)
			reachability.ExpectAllIngress("x/b", true)
			reachability.ExpectAllIngress("x/c", true)

			policyAllowAll := netpol.GetAllowAll("allow-all-2")
			validateOrFailFunc(k8s, f, "x", 82, 81, policyAllowAll, reachability, false, scenario)

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

			ginkgo.By("Making sure ingress doesn't work other than port 80")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllEgress("x/a", false)
			reachability.ExpectAllEgress("x/b", false)
			reachability.ExpectAllEgress("x/c", false)
			reachability.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachability, true, scenario)

			ginkgo.By("Alloing all ports")
			reachability.ExpectAllEgress("x/a", true)
			reachability.ExpectAllEgress("x/b", true)
			reachability.ExpectAllEgress("x/c", true)

			policy2 := netpol.GetDefaultAllAllowEggress("allow-all-2")
			validateOrFailFunc(k8s, f, "x", 82, 81, policy2, reachability, false, scenario)

		})

		ginkgo.It("should stop enforcing policies after they are deleted [Feature:NetworkPolicy]", func() {

			ginkgo.By("Creating a network policy for the server which denies all traffic.")
			policy := netpol.GetDefaultALLDenyPolicy("deny-all")
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.AllowLoopback()
			scenario.forEach(func(from, to netpol.PodString) {
				if from.Namespace() == "x" || to.Namespace() == "x" {
					if from != to {
						reachability.Expect(from, to, false)
					}
				}
			})
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)

			//err := k8s.CleanNetworkPolicies(scenario.namespaces)
			//			//time.Sleep(1 * time.Second)
			//			//if err != nil {
			//			//	ginkgo.Fail(fmt.Sprintf("%v", err))
			//			//}
			reachability = netpol.NewReachability(scenario.allPods, true)
			validateOrFailFunc(k8s, f, "x", 82, 80, nil, reachability, false, scenario)
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
			validateOrFailFunc(k8s, f, "x", 82, 80, policy, reachability, true, scenario)

			ginkgo.By("Creating a network policy for pod-a which allows Egress traffic to pod-b.")

			egressPolicyAllowToB := netpol.GetPolicyWithEgressRuleOnlyPodSelector("x", "a", "b")

			reachability = netpol.NewReachability(scenario.allPods, true)
			// Using for each?
			for _, nn := range []string{"x", "y", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect("x/a", netpol.NewPod(nn, pp), false)
				}
			}
			reachability.Expect("x/a", "x/a", true)
			reachability.Expect("x/a", "x/b", true)

			validateOrFailFunc(k8s, f, "x", 82, 80, egressPolicyAllowToB, reachability, true, scenario)

			ginkgo.By("Creating a network policy for pod-a that denies traffic from pod-b.")
			policyDenyFromPodB := netpol.GetDefaultDenyIngressPolicy("deny-all")

			reachability2 := netpol.NewReachability(scenario.allPods, true)

			reachability2.ExpectAllIngress(netpol.PodString("x/a"), false)
			reachability2.ExpectAllIngress(netpol.PodString("x/b"), false)
			reachability2.ExpectAllIngress(netpol.PodString("x/c"), false)
			reachability2.AllowLoopback()
			validateOrFailFunc(k8s, f, "x", 82, 80, policyDenyFromPodB, reachability2, true, scenario)
		})

		ginkgo.It("should allow egress access to server in CIDR block [Feature:NetworkPolicy]", func() {

			// Getting podServer's status to get podServer's IP, to create the CIDR
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to pod a in namespace x")
			pod := podList.Items[0]

			podServerCIDR := fmt.Sprintf("%s/32", pod.Status.PodIP)

			policyAllowCIDR := netpol.PolicyAllowCIDR("x", "a", podServerCIDR)

			reachability := netpol.NewReachability(scenario.allPods, true)
			// using foreach?
			for _, nn := range []string{"x", "y", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability.Expect("x/a", netpol.NewPod(nn, pp), false)
				}
			}
			reachability.Expect("x/a", "x/a", true)

			validateOrFailFunc(k8s, f, "x", 82, 80, policyAllowCIDR, reachability, true, scenario)
		})

		ginkgo.It("should enforce except clause while egress access to server in CIDR block [Feature:NetworkPolicy]", func() {

			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to pod a in namespace x")
			pod := podList.Items[0]

			podServerAllowCIDR := fmt.Sprintf("%s/4", pod.Status.PodIP)
			policyAllowCIDR := netpol.PolicyAllowCIDR("x", "a", podServerAllowCIDR)

			podList, err = f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to pod b in namespace x")
			podb := podList.Items[0]

			// Exclude podServer's IP with an Except clause
			podServerExceptList := []string{fmt.Sprintf("%s/32", podb.Status.PodIP)}
			policyAllowCIDR.Spec.Egress[0].To[0].IPBlock.Except = podServerExceptList

			reachability := netpol.NewReachability(scenario.allPods, true)

			reachability.Expect("x/a", "x/b", false)

			validateOrFailFunc(k8s, f, "x", 82, 80, policyAllowCIDR, reachability, true, scenario)
		})

		ginkgo.It("should ensure an IP overlapping both IPBlock.CIDR and IPBlock.Except is allowed [Feature:NetworkPolicy]", func() {
			// Getting podServer's status to get podServer's IP, to create the CIDR with except clause
			podList, err := f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=a"})
			framework.ExpectNoError(err, "Failing to pod a in namespace x")
			pod := podList.Items[0]

			podServerAllowCIDR := fmt.Sprintf("%s/4", pod.Status.PodIP)
			policyAllowCIDR := netpol.PolicyAllowCIDR("x", "a", podServerAllowCIDR)

			podList, err = f.ClientSet.CoreV1().Pods("x").List(context.TODO(), metav1.ListOptions{LabelSelector: "pod=b"})
			framework.ExpectNoError(err, "Failing to pod b in namespace x")
			podb := podList.Items[0]

			// Exclude podServer's IP with an Except clause
			podServerExceptList := []string{fmt.Sprintf("%s/32", podb.Status.PodIP)}
			policyAllowCIDR.Spec.Egress[0].To[0].IPBlock.Except = podServerExceptList

			reachability := netpol.NewReachability(scenario.allPods, true)

			reachability.Expect("x/a", "x/b", false)

			validateOrFailFunc(k8s, f, "x", 82, 80, policyAllowCIDR, reachability, true, scenario)

			podbIp := fmt.Sprintf("%s/32", podb.Status.PodIP)
			//// Create NetworkPolicy which allows access to the podServer using podServer's IP in allow CIDR.
			allowPolicy := netpol.PolicyAllowCIDR("x", "a", podbIp)
			reachability_2 := netpol.NewReachability(scenario.allPods, true)
			for _, nn := range []string{"x", "y", "z"} {
				for _, pp := range []string{"a", "b", "c"} {
					reachability_2.Expect("x/a", netpol.NewPod(nn, pp), false)
				}
			}
			reachability_2.Expect("x/a", "x/b", true)
			reachability_2.Expect("x/a", "x/a", true)
			validateOrFailFunc(k8s, f, "x", 82, 80, allowPolicy, reachability_2, false, scenario)
		})

		// NOTE: SCTP protocol is not in Kubernetes 1.19 so this test will fail locally.
		ginkgo.It("should not allow access by TCP when a policy specifies only SCTP [Feature:NetworkPolicy] [Feature:SCTP]", func() {

			policy := netpol.AllowSCTPBasedOnPodSelector("allow-only-sctp-ingress-on-port-81", map[string]string{"pod": "a"}, &intstr.IntOrString{IntVal:81})
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
			reachability := netpol.NewReachability(scenario.allPods, true)
			reachability.ExpectAllIngress("x/a", false)
			//TODO check SCTP is not module is not avalible at time of testing
			validateOrFailFunc(k8s, f, "x", 82, 81, policy, reachability, true, scenario)
		})

	})
})
