package networkpolicy

/**
   The deny-all policy
   kind: NetworkPolicy
   apiVersion: networking.k8s.io/v1
   metadata:
     name: web-deny-all
   spec:
     podSelector:
     matchLabels:
       app: web
   ingress: []
 */
denyIngressPolicy := &networkingv1.NetworkPolicy{
	ObjectMeta: metav1.ObjectMeta{
		Name: "deny-ingress",
	},
	Spec: networkingv1.NetworkPolicySpec{
		PodSelector: metav1.LabelSelector{},
		Ingress:     []networkingv1.NetworkPolicyIngressRule{},
	},
}
