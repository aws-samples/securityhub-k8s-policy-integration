#!/bin/bash

if ! hash aws 2>/dev/null || ! hash pip3 2>/dev/null; then
    echo "This script requires the AWS cli, and pip3 installed"
    exit 2
fi

if [ -z "$AWS_REGION" ]; then
  echo "Error: Please setup AWS_REGION environment variable"
  exit 1
fi

set -eo pipefail

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

BUCKET_NAME=aws-securityhub-k8s-policy-"$ACCOUNT_ID"-"$AWS_REGION"
aws s3 mb s3://"$BUCKET_NAME" || true

rm -rf lambda_build ; mkdir lambda_build ; cd lambda_build
cp -r ../function/* .
pip3 install --target . -r requirements.txt
cd ../
aws cloudformation package --template-file template.yml --s3-bucket "$BUCKET_NAME" --output-template-file out.yml
aws cloudformation deploy --template-file out.yml \
  --stack-name aws-securityhub-k8s-policy-integration \
  --parameter-overrides file://./parameters.json \
  --capabilities CAPABILITY_NAMED_IAM
