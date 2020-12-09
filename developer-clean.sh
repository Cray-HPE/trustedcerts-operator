kubectl delete deployments,service -l control-plane=controller-manager
kubectl delete role,rolebinding --all
make uninstall
