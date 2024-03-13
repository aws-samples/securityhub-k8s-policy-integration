#!/bin/bash

if ! hash aws 2>/dev/null; then
    echo "This script requires the AWS cli installed"
    exit 2
fi

set -eo pipefail

clean_up_kyverno() {
    echo "Deleting demo Kyverno resources"
    kubectl delete ns non-compliant
    kubectl delete clusterpolicy require-ns-labels
    echo "Uninstalling Kyverno"
    kubectl delete -f https://github.com/kyverno/kyverno/releases/download/v1.10.0/install.yaml
}

clean_up_gatekeeper() {
    echo "Deleting demo Gatekeeper resources"
    kubectl delete ns non-compliant
    kubectl delete constraint ns-must-have-gk
    kubectl delete constrainttemplate k8srequiredlabels
    echo "Uninstalling Gatekeeper"
    kubectl delete -f https://github.com/kyverno/kyverno/releases/download/v1.10.0/install.yaml
}

clean_up_roles() {
    kubectl delete clusterrole read-only
    kubectl delete clusterrolebinding read-only-binding
}

ROLE_ARN=$(aws cloudformation describe-stacks --stack-name aws-securityhub-k8s-policy-integration --query "Stacks[0].Outputs[?OutputKey=='Role'].OutputValue" --output text)

while true; do
    read -p "Do you want to uninstall Kyverno? (y/n)" response
    case $response in
        [Yy]* ) clean_up_kyverno;;
        [Nn]* ) break;;
        * ) echo "Response must start with y or n.";;
    esac
done

while true; do
    read -p "Do you want to uninstall Gatekeeper? (y/n)" response
    case $response in
        [Yy]* ) clean_up_gatekeeper;;
        [Nn]* ) break;;
        * ) echo "Response must start with y or n.";;
    esac
done

echo "Enter your cluster name to delete kubernetes resources: "  
read CLUSTER_NAME

while true; do
    read -p "Do you want delete the aws-auth configmap entry? (y/n)" response
    case $response in
        [Yy]* ) eksctl delete iamidentitymapping --cluster "$CLUSTER_NAME" --group read-only-group --arn "$ROLE_ARN"; break;;
        [Nn]* ) break;;
        * ) echo "Response must start with y or n.";;
    esac
done

while true; do
    read -p "Do you want to delete the Role and RoleBinding? (y/n)" response
    case $response in
        [Yy]* ) clean_up_roles; break;;
        [Nn]* ) break;;
        * ) echo "Response must start with y or n.";;
    esac
done


STACK=aws-securityhub-k8s-policy-integration
BUCKET_NAME=aws-securityhub-k8s-policy-"$ACCOUNT_ID"-"$AWS_REGION"

echo "Deleting Cloudformation stack $STACK."

aws cloudformation delete-stack --stack-name "$STACK"
echo "Deleted $STACK stack."

echo "Deleting S3 bucket $BUCKET_NAME."
aws s3 rb --force "s3://$BUCKET_NAME"

rm -f out.yml out.json lambda_build/
