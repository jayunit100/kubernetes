package utils

import (
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GetDefaultDenyPolicy returns a default deny policy named 'name'.
// kind: NetworkPolicy
//  apiVersion: networking.k8s.io/v1
//  metadata:
//    name: name
//  spec:
//    podSelector:
//      matchLabels:
//        app: web
//    ingress: []
func GetDefaultDenyPolicy(name string) *networkingv1.NetworkPolicy {
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
