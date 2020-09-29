package utils

import (
	"fmt"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetDefaultDenyPolicy returns a default deny policy named 'name'.
// 	 Note we have several defaults that are empty/nil here.
//   - Empty podSelector:  this means that *all* Pods in the namespace are selected.
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

// GetRandomIngressPolicies returns "num" random policies that whitelist a unique:n label, i.e.
// unique:1, unique:2, and so on.  Used for creating a 'background' set of policies.
func GetRandomIngressPolicies(num int) []*networkingv1.NetworkPolicy {
	policies := []*networkingv1.NetworkPolicy{}

	for i := 0; i < num; i++ {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name: fmt.Sprintf("allow-all-%v", i),
			},
			Spec: networkingv1.NetworkPolicySpec{
				// Allow all traffic
				PodSelector: metav1.LabelSelector{
					MatchLabels: map[string]string{
						"unique": fmt.Sprintf("%v", i),
					},
				},
				Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
			},
		}
		policies = append(policies, policy)
	}
	return policies
}

func GetAllowAllIngressPolicy(name string) *networkingv1.NetworkPolicy {
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

func GetAllowIngressByPodSelectorPolicy(name string, podSelectorLabels map[string]string, podSelectorLabelsOtherNs *metav1.LabelSelector) *networkingv1.NetworkPolicy {
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
	nameSpaceSelectorOtherNs *metav1.LabelSelector, podSelectorLabelsOtherNs *metav1.LabelSelector) *networkingv1.NetworkPolicy {
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
					PodSelector:       podSelectorLabelsOtherNs,
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
	nameSpaceSelectorOtherNs *metav1.LabelSelector, podSelectorLabelsOtherNs *metav1.LabelSelector) *networkingv1.NetworkPolicy {
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
					PodSelector:       podSelectorLabelsOtherNs,
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
							PodSelector:       egressPodSelector,
						},
					},
				},
			},
		},
	}
	return policy
}

func GetPolicyWithEgressRule_legacy(ns string, name string, toNs string, toPod string) *networkingv1.NetworkPolicy {
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

func GetDefaultAllAllowEgress() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allow-all",
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply this policy to all Pods
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

func AllowSCTPBasedOnPodSelector(name string, podSelectorLabels map[string]string, portNum *intstr.IntOrString) *networkingv1.NetworkPolicy {
	protocolSCTP := v1.ProtocolSCTP
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply to server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
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

// AllowProtocolBasedOnPodSelector is a base network policy template which distinguishes between the types of v1.Protocol available in v1 core
func AllowProtocolBasedOnPodSelector(name string, protocol v1.Protocol, podSelectorLabels map[string]string, portNum *intstr.IntOrString) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Apply to server
			PodSelector: metav1.LabelSelector{
				MatchLabels: podSelectorLabels,
			},
			// Allow traffic only via protoSpec on port
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				Ports: []networkingv1.NetworkPolicyPort{{
					Port:     portNum,
					Protocol: &protocol,
				}},
			}},
		},
	}
	return policy
}
