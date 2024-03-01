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

while true; do
    read -p "Do you want to uninstall Kyverno? (y/n)" response
    case $response in
        [Yy]* ) clean_up_kyverno
        [Nn]* ) break;;
        * ) echo "Response must start with y or n.";;
    esac
done

while true; do
    read -p "Do you want to uninstall Gatekeeper? (y/n)" response
    case $response in
        [Yy]* ) clean_up_gatekeeper
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
