/*
Copyright 2020 The Kubernetes Authors.

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
package utils

import (
	"fmt"
	"k8s.io/apimachinery/pkg/util/intstr"

	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetDenyIngress returns a default deny policy named 'name'.
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
func GetDenyIngress(name string) *networkingv1.NetworkPolicy {
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

// GetAllowIngress allows all ingress
func GetAllowIngress(name string) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{}},
		},
	}
	return policy
}

// GetAllowIngressByPort allows ingress by port
func GetAllowIngressByPort(name string, port *intstr.IntOrString) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: port},
					},
				},
			},
		},
	}
	return policy
}

// GetAllowEgressByPort allows egress by port
func GetAllowEgressByPort(name string, port *intstr.IntOrString) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					Ports: []networkingv1.NetworkPolicyPort{
						{Port: port},
					},
				},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
	return policy
}

// GetDenyAll denies ingress traffic, AS WELL as egress traffic.
// - BOTH policy types must be specified
// - The Egress rule must (like the ingress default rule) be a array with 0 values.
func GetDenyAll(name string) *networkingv1.NetworkPolicy {
	policy := GetDenyIngress(name)
	policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress}
	policy.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{}
	return policy
}

// GetAllowIngressByPod allows ingress by pod labels
func GetAllowIngressByPod(name string, targetLabels map[string]string, peerPodSelector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					PodSelector: peerPodSelector,
				}},
			}},
		},
	}
	return policy
}

// GetDenyIngressForTarget denies all ingress for target
func GetDenyIngressForTarget(targetSelector metav1.LabelSelector) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deny-ingress-via-label-selector",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: targetSelector,
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress:     []networkingv1.NetworkPolicyIngressRule{},
		},
	}
}

// GetAllowIngressByNamespace allows ingress for namespace
func GetAllowIngressByNamespace(name string, targetLabels map[string]string, peerNamespaceSelector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: peerNamespaceSelector,
				}},
			}},
		},
	}
	return policy
}

// GetAllowIngressByNamespaceAndPort allows ingress for namespace AND port
func GetAllowIngressByNamespaceAndPort(name string, targetLabels map[string]string, peerNamespaceSelector *metav1.LabelSelector, port *intstr.IntOrString) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: peerNamespaceSelector,
				}},
				Ports: []networkingv1.NetworkPolicyPort{
					{Port: port},
				},
			}},
		},
	}
	return policy
}

// GetAllowIngressByNamespaceOrPod allows ingress for pods with matching namespace OR pod labels
func GetAllowIngressByNamespaceOrPod(name string, targetLabels map[string]string, peerNamespaceSelector *metav1.LabelSelector, peerPodSelector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{
					{
						NamespaceSelector: peerNamespaceSelector,
					},
					{
						PodSelector: peerPodSelector,
					},
				},
			}},
		},
	}
	return policy
}

// GetAllowIngressByNamespaceAndPod allows ingress for pods with matching namespace AND pod labels
func GetAllowIngressByNamespaceAndPod(name string, targetLabels map[string]string, peerNamespaceSelector *metav1.LabelSelector, peerPodSelector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: peerNamespaceSelector,
					PodSelector:       peerPodSelector,
				}},
			}},
		},
	}
	return policy
}

// GetAllowEgressByNamespaceAndPod allows egress for pods with matching namespace AND pod labels
func GetAllowEgressByNamespaceAndPod(name string, targetLabels map[string]string, peerNamespaceSelector *metav1.LabelSelector, peerPodSelector *metav1.LabelSelector) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: peerNamespaceSelector,
							PodSelector:       peerPodSelector,
						},
					},
				},
			},
		},
	}
	return policy
}

// GetAllowEgress allows all egress
func GetAllowEgress() *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allow-egress",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}
}

// GetAllowEgressByPod allows egress by pod labels
func GetAllowEgressByPod(name string, toPod string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("allow-egress-by-pod-%s-%s", name, toPod),
		},
		Spec: networkingv1.NetworkPolicySpec{
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

// GetAllowEgressByCIDR creates an egress netpol with an ipblock
func GetAllowEgressByCIDR(podname string, podserverCIDR string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allow-client-a-via-cidr-egress-rule",
		},
		Spec: networkingv1.NetworkPolicySpec{
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

// GetAllowEgressByCIDRExcept creates an egress netpol with an ipblock and except
func GetAllowEgressByCIDRExcept(podname string, podserverCIDR string, except []string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allow-client-a-via-cidr-egress-rule",
		},
		Spec: networkingv1.NetworkPolicySpec{
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
								CIDR:   podserverCIDR,
								Except: except,
							},
						},
					},
				},
			},
		},
	}
}

// GetAllowIngressOnSCTPByPort allows ingress on protocol SCTP by port
func GetAllowIngressOnSCTPByPort(name string, targetLabels map[string]string, portNum *intstr.IntOrString) *networkingv1.NetworkPolicy {
	protocolSCTP := v1.ProtocolSCTP
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
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

// GetAllowIngressOnProtocolByPort is a base network policy template which distinguishes between the types of v1.Protocol available in v1 core
func GetAllowIngressOnProtocolByPort(name string, protocol v1.Protocol, targetLabels map[string]string, portNum *intstr.IntOrString) *networkingv1.NetworkPolicy {
	policy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: targetLabels,
			},
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
