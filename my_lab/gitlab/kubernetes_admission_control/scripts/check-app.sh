#!/bin/bash
set -e

export KUBECONFIG=/home/shamrat/.kube/config

echo "Checking Kubernetes connection..."
kubectl config current-context
kubectl get nodes

echo "Checking service..."
kubectl get svc -n pep-test
kubectl get pods -n pep-test

MINIKUBE_IP=$(minikube ip)
APP_URL="http://$MINIKUBE_IP:30221"

echo "Checking app URL:"
echo "$APP_URL"

curl -v "$APP_URL"