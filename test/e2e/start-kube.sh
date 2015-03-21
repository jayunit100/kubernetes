for SERVICES in etcd kube-apiserver kube-controller-manager kube-scheduler; do 
    systemctl restart $SERVICES
    systemctl enable $SERVICES
    systemctl status $SERVICES 
done

echo "services"
for SERVICES in kube-proxy kubelet docker; do 
    echo $SERVICES 
    	systemctl restart $SERVICES
    systemctl enable $SERVICES
    systemctl status $SERVICES 
done

