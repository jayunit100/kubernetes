package utils

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

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

// GetDefaultALLDenyPolicy denies ingress traffic, AS WELL as egress traffic.
// - BOTH policy types must be specified
// - The Egress rule must (like the ingress default rule) be a array with 0 values.
func GetDefaultALLDenyPolicy(name string) *networkingv1.NetworkPolicy {
	policy := GetDefaultDenyIngressPolicy(name)
	policy.Spec.PolicyTypes = []networkingv1.PolicyType{networkingv1.PolicyTypeEgress, networkingv1.PolicyTypeIngress}
	policy.Spec.Egress= []networkingv1.NetworkPolicyEgressRule{}
	return policy
}

func GetAllowBasedOnPodSelector(name string, podSelectorLabels map[string]string, ingressLabels map[string]string)  *networkingv1.NetworkPolicy {
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
					PodSelector: &metav1.LabelSelector{
						MatchLabels: ingressLabels,
					},
				}},
			}},
		},
	}
	return policy
}

func GetAllowBasedOnNamespaceSelector(name string, podSelectorLabels map[string]string, ingressLabels map[string]string)  *networkingv1.NetworkPolicy {
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
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: ingressLabels,
					},
				}},
			}},
		},
	}
	return policy
}