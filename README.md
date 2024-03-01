# Integrating Kubernetes Policy-as-code solutions with AWS Security Hub

This solution enables Kubernetes administrators to send audit findings of their Kubernetes Policy-as-code solutions (such as Kyverno, Gatekeeper) to AWS Security Hub.

## Prerequisites

## Deploying a new integration

1. Configure `parameters.json` with:
* `Policy`: Name of the product that you want to enable. `gatekeeper` or `policyreport` (Default [Kubernetes Policy report](https://github.com/kubernetes-sigs/wg-policy-prototypes/tree/master/policy-report) used by tools such as Kyverno). 
* `SubnetIds`: (Optional) A comma separated value of subnets. You will need to configure if you've configured your EKS cluster API endpoints as private only, remove if your AWS EKS clusters have public endpoint enabled.
* `SecurityGroupId`: (Optional) A security group ID that allows connectivity to the EKS clusters. Only required if running only private API endpoints, otherwise you can remove it. This security group should be allowed ingress from the Amazon EKS control plane security group.
* `AccessEntryEnabled`: AccessEntryEnabled — (Optional) If you’re using AWS EKS access entries, the solution will automatically deploy the access entries AmazonEKSClusterAdminPolicy for the integration to access your EKS clusters.
* `ClusterNames`: (Optional) When deploying access entries, this is the list of cluster names to configure access entries for.
2. Run `./deploy.sh`

## Disabling integration

To disable the integration run `./cleanup.sh` from your terminal.

## Testing Kyverno integration

1. Install Kyverno: 
```kubectl create -f https://github.com/kyverno/kyverno/releases/download/v1.10.0/install.yaml```
2. Setup a non-compliant policy (example requiring labels for namespaces) such as:
```kubectl create -f - << EOF
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-ns-labels
spec:
  validationFailureAction: Audit
  background: true
  rules:
  - name: check-for-labels-on-namespace
    match:
      any:
      - resources:
          kinds:
          - Namespace
    validate:
      message: "The label thisshouldntexist is required."
      pattern:
        metadata:
          labels:
            thisshouldntexist: "?*"
EOF
```
3. Create run a non compliant namespace with:
```kubectl create namespace non-compliant```
4. Check the Kubernetes policy report status with:
```kubectl get clusterpolicies```

## Integrating Gatekeeper

1. Install Gatekeeper:
```kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/v3.14.0/deploy/gatekeeper.yaml```
2. Create run a non compliant namespace with:
```kubectl create namespace non-compliant```
3. Setup policy constraint template and constraint (namespace should be labelled with gatekeeper):
```kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/demo/basic/templates/k8srequiredlabels_template.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/demo/basic/constraints/all_ns_must_have_gatekeeper.yaml
```
4. Check the constraint status with:
``` kubectl describe constraints ns-must-have-gk```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

