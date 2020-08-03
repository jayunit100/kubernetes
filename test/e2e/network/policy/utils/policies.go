package utils

import (
	"k8s.io/apimachinery/pkg/util/intstr"
	"time"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// common for all tests.  these get hardcoded into the Expect() clauses,
// so, we cant easily parameterize them (well, we could, but that would
// make the code harder to interpret).
var pods []string
var namespaces []string
var p80 int
var p81 int
var allPods []PodString
var podIPs map[string]string

func init() {
	p80 = 80
	p81 = 81
	pods = []string{"a", "b", "c"}
	namespaces = []string{"x", "y", "z"}
	podIPs = make(map[string]string, len(pods)*len(namespaces))
	for _, podName := range pods {
		for _, ns := range namespaces {
			allPods = append(allPods, NewPod(ns, podName))
		}
	}
}

func waitForHTTPServers(k8s *Kubernetes) error {
	const maxTries = 10
	const sleepInterval = 1 * time.Second
	log.Infof("waiting for HTTP servers (ports 80 and 81) to become ready")
	var wrong int
	for i := 0; i < maxTries; i++ {
		reachability := NewReachability(allPods, true)
		Validate(k8s, reachability, 82, 80)
		Validate(k8s, reachability, 82, 81)
		_, wrong, _ = reachability.Summary()
		if wrong == 0 {
			log.Infof("all HTTP servers are ready")
			return nil
		}
		log.Debugf("%d HTTP servers not ready", wrong)
		time.Sleep(sleepInterval)
	}
	return errors.Errorf("after %d tries, %d HTTP servers are not ready", maxTries, wrong)
}

func waitForPodInNamespace(k8s *Kubernetes, ns string, pod string) error {
	log.Infof("waiting for pod %s/%s", ns, pod)
	for {
		k8sPod, err := k8s.GetPod(ns, pod)
		if err != nil {
			return errors.WithMessagef(err, "unable to get pod %s/%s", ns, pod)
		}

		if k8sPod != nil && k8sPod.Status.Phase == v1.PodRunning {
			if k8sPod.Status.PodIP == "" {
				return errors.WithMessagef(err, "unable to get IP of pod %s/%s", ns, pod)
			} else {
				log.Debugf("IP of pod %s/%s is: %s", ns, pod, k8sPod.Status.PodIP)
				podIPs[ns+"/"+pod] = k8sPod.Status.PodIP
			}

			log.Debugf("pod running: %s/%s", ns, pod)
			return nil
		}
		log.Infof("pod %s/%s not ready, waiting ...", ns, pod)
		time.Sleep(2 * time.Second)
	}
}

func Validate(k8s *Kubernetes, reachability *Reachability, fromPort, toPort int) {
	type probeResult struct {
		podFrom   PodString
		podTo     PodString
		connected bool
		err       error
		command   string
	}
	k8s.ClearCache()
	numProbes := len(allPods) * len(allPods)
	resultsCh := make(chan *probeResult, numProbes)
	// TODO: find better metrics, this is only for POC.
	oneProbe := func(podFrom, podTo PodString) {
		//		log.Infof("Probing: %s -> %s", podFrom, podTo)
		connected, err, command := k8s.Probe(podFrom.Namespace(), podFrom.PodName(), podTo.Namespace(), podTo.PodName(), fromPort, toPort)
		resultsCh <- &probeResult{podFrom, podTo, connected, err, command}
	}
	for _, pod1 := range allPods {
		for _, pod2 := range allPods {
			go oneProbe(pod1, pod2)
			time.Sleep(50 * time.Millisecond)
		}
	}
	for i := 0; i < numProbes; i++ {
		r := <-resultsCh
		//		log.Infof("Received result %v!", r.podFrom, r.podTo, r.connected, r.err)
		if r.err != nil {
			log.Infof("unable to perform probe %s -> %s: %v", r.podFrom, r.podTo, r.err)
		}
		reachability.Observe(r.podFrom, r.podTo, r.connected)
		expected := reachability.Expected.Get(r.podFrom.String(), r.podTo.String())
		if r.connected != expected {
			log.Infof("Validation of ", r.podFrom, r.podTo, " FAILED !!! \n")
			log.Infof("error %v ", r.err)
			if expected {
				log.Infof("Whitelisted pod connection was BLOCKED --- run '", r.command, "' to reproduce.")
			} else {
				log.Infof("Blacklisted pod connection was ALLOWED --- run '", r.command, "' to reproduce.")
			}
		}
	}

}

// GetDefaultDenyPolicy returns a default deny policy named 'name'.
// 	 Note we have several defaults that are empty/nil here.
//   - Empty podSelector:  this means that *all* pods in the namespace are selected.
//   - No Selector type: this means we default to Ingress.
//
// Equivalent YAML:
//
// kind: NetworkPolicy
//  apiVersion: networking.k8s.io/v1
//  metadata:
//    name: name
//  spec:
//    podSelector:
//    ingress: []
func GetDefaultDenyIngressPolicy(name string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{},
		},
	}
}

func GetAllowAll(name string) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Allow all traffic
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
		},
	}
	return policy
}

// GetDefaultALLDenyPolicy denies ingress traffic, AS WELL as egress traffic.
// - BOTH policy types must be specified
// - The Egress rule must (like the ingress default rule) be a array with 0 values.
func GetDefaultALLDenyPolicy(name string) *networkingv1.NetworkPolicy {
	policy := GetDefaultDenyIngressPolicy(name)
	policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress}
	policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{}
	return policy
}

func GetAllowBasedOnPodSelector(name string, podSelectorLabels map[string]string, podSelectorLabelsOtherNs *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the Server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
			// Allow traffic only from client-a
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: podSelectorLabelsOtherNs,
				}},
			}},
		},
	}
	return policy
}

func GetAllowBasedOnPodSelectorandNamespaceSelectorFromOtherNamespace(ns1 string, name string, podSelectorLabels map[string]string,
	nameSpaceSelectorOtherNs *metav1.LabelSelector, podSelectorLabelsOtherNs *metav1.LabelSelector) * networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns1,
			Name:      name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the Server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
			// Allow traffic only from a pod in different namespace
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: nameSpaceSelectorOtherNs,
					PodSelector: podSelectorLabelsOtherNs,
				}},
			}},
		},
	}
	return policy
}

func GetAllowBasedOnNamespaceSelector(name string, podSelectorLabels map[string]string, s *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the Server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
			// Allow traffic only from client-a
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: s,
				}},
			}},
		},
	}
	return policy
}

func GetAllowBasedOnPodSelectorandNamespaceSelector(name string, podSelectorLabels map[string]string,
	nameSpaceSelectorOtherNs *metav1.LabelSelector, podSelectorLabelsOtherNs *metav1.LabelSelector) * networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the Server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
			// Allow traffic only from a pod in different namespace
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: nameSpaceSelectorOtherNs,
					PodSelector: podSelectorLabelsOtherNs,
				}},
			}},
		},
	}
	return policy
}


// TODO Discuss do we want to pass string(support only single field) or labelselector(support multiple fields) as function arg
func GetPolicyWithEgressrule(ns string, name string, podLabelSelector map[string]string, egressNsSelector *metav1.LabelSelector, egressPodSelector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the client
			PodSelector: metav1.LabelSelector{
				MatchLabels: podLabelSelector,
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			// Allow traffic only to server-a in namespace-b
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: egressNsSelector,
							PodSelector: egressPodSelector,
						},
					},
				},
			},
		},
	}
	return policy
}


func GetPolicyWithEgressRule_lagacy(ns string, name string, toNs string, toPod string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the client
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": name,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			// Allow traffic only to server-a in namespace-b
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"ns": toNs,
								},
							},
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod": toPod,
								},
							},
						},
					},
				},
			},
		},
	}
}

func GetDefaultAllAllowEggress(name string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
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
}

func GetPolicyWithEgressRuleOnlyPodSelector(ns string, name string, toPod string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the client
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": name,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{
									"pod": toPod,
								},
							},
						},
					},
				},
			},
		},
	}
}

func PolicyAllowCIDR(namespace string, podname string, podserverCIDR string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      "allow-client-a-via-cidr-egress-rule",
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to the Server
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{
					"pod": podname,
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			// Allow traffic to only one CIDR block.
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							IPBlock: &networkingv1.IPBlock{
								CIDR: podserverCIDR,
							},
						},
					},
				},
			},
		},
	}
}

func AllowSCTPBasedOnPodSelector(name string, podSelectorLables map[string]string, portNum *intstr.IntOrString) *networkingv1.NetworkPolicy{
	protocolSCTP := v1.ProtocolSCTP
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply to server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLables,
			},
			// Allow traffic only via SCTP on port 80 .
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{
					Port:     portNum,
					Protocol: &protocolSCTP,
				}},
			}},
		},
	}
	return policy
}
