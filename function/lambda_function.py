"Lambda functions list pods in EKS cluster"
import base64
import datetime
import logging
import os
import re

import boto3
from botocore.signers import RequestSigner
from kubernetes import client, config
from kubernetes.client.rest import ApiException

RECORDSTATE_ARCHIVED = "ARCHIVED"
RECORDSTATE_ACTIVE = "ACTIVE"
TYPE_PREFIX = "Software and Configuration Checks/Kubernetes Policies/"

logger = logging.getLogger()
logger.setLevel(logging.INFO)

STS_TOKEN_EXPIRES_IN = 60
session = boto3.session.Session()
sts = session.client("sts")
service_id = sts.meta.service_model.service_id
eks = boto3.client("eks")
securityhub = boto3.client("securityhub")
cluster_cache = {}


def get_cluster_info(cluster_name):
    """Retrieve cluster endpoint and certificate"""
    cluster_info = eks.describe_cluster(name=cluster_name)
    endpoint = cluster_info["cluster"]["endpoint"]
    cert_authority = cluster_info["cluster"]["certificateAuthority"]["data"]
    cluster_info = {"endpoint": endpoint, "ca": cert_authority}
    return cluster_info


def get_bearer_token(cluster_name):
    """Create authentication token"""
    signer = RequestSigner(
        service_id,
        session.region_name,
        "sts",
        "v4",
        session.get_credentials(),
        session.events,
    )
    params = {
        "method": "GET",
        "url": "https://sts.{}.amazonaws.com/"
        "?Action=GetCallerIdentity&Version=2011-06-15".format(session.region_name),
        "body": {},
        "headers": {"x-k8s-aws-id": cluster_name},
        "context": {},
    }
    signed_url = signer.generate_presigned_url(
        params,
        region_name=session.region_name,
        expires_in=STS_TOKEN_EXPIRES_IN,
        operation_name="",
    )
    base64_url = base64.urlsafe_b64encode(signed_url.encode("utf-8")).decode("utf-8")
    # remove any base64 encoding padding:
    return "k8s-aws-v1." + re.sub(r"=*", "", base64_url)


def get_kube_config(cluster_name):
    """Get kubeconfig for cluster"""
    if cluster_name in cluster_cache:
        cluster = cluster_cache[cluster_name]
    else:
        # not present in cache retrieve cluster info from EKS service
        cluster = get_cluster_info(cluster_name)
        # store in cache for execution environment resuse
        cluster_cache[cluster_name] = cluster
    kubeconfig = {
        "apiVersion": "v1",
        "clusters": [
            {
                "name": cluster_name,
                "cluster": {
                    "certificate-authority-data": cluster["ca"],
                    "server": cluster["endpoint"],
                },
            }
        ],
        "contexts": [
            {
                "name": f"context-{cluster_name}",
                "context": {"cluster": cluster_name, "user": f"user-{cluster_name}"},
            }
        ],
        "current-context": f"context-{cluster_name}",
        "kind": "Config",
        "preferences": {},
        "users": [
            {
                "name": f"user-{cluster_name}",
                "user": {"token": get_bearer_token(cluster_name)},
            }
        ],
    }
    return kubeconfig


def archive_past_violations(policy_source, new_findings):
    """Archive Security hub findings that were not added"""
    new_recorded_time = datetime.datetime.utcnow().isoformat() + "Z"
    archived = []
    new_ids = [finding["Id"] for finding in new_findings]

    paginator = securityhub.get_paginator("get_findings")
    findings_for_check_pages = paginator.paginate(
        Filters={
            "Type": [
                {
                    "Value": TYPE_PREFIX + policy_source,
                    "Comparison": "PREFIX",
                },
            ],
            "RecordState": [{"Value": RECORDSTATE_ACTIVE, "Comparison": "EQUALS"}],
        },
    )

    for previous_findings in findings_for_check_pages:
        for finding in previous_findings["Findings"]:
            if not finding["Id"] in new_ids:
                finding["UpdatedAt"] = new_recorded_time
                finding["RecordState"] = RECORDSTATE_ARCHIVED
                archived.append(finding)

    if len(archived) > 0:
        import_new_findings(archived)


def import_new_findings(new_findings):
    """Import new audit findings to Security Hub"""
    try:
        for i in range(0, len(new_findings), 100):
            response = securityhub.batch_import_findings(
                Findings=new_findings[i : i + 100],
            )
            if response["FailedCount"] > 0:
                logger.warning(
                    "Failed to import {} findings".format(
                        response["FailedCount"],
                    ),
                )
            else:
                logger.info(f'{len(new_findings)} Findings imported to Security Hub')
    except Exception as error:
        logger.error("Error:  %s", error)
        raise


def map_policy_violation_to_asff(cluster, rule, violation):
    """Create a Security Hub finding based on Policy Report violation"""
    severity = rule["metadata"].get("annotations", {}).get("severity", "MEDIUM")
    policy_name = violation["policy"]
    resource_type = "AwsEks"
    cluster_name = cluster["clusterName"]
    account_id = cluster["accountId"]
    region = cluster["region"]
    partition = cluster["partition"]
    resource_violation = violation["resources"][0]
    source = violation["source"]

    # If no namespace, it's a cluster report violation
    resource_violation["namespace"] = resource_violation.get("namespace", "")
    violation_id = f'eks-{cluster_name}-{resource_violation["namespace"]}-{resource_violation["kind"]}-{resource_violation["name"]}'

    resource_id = f"arn:{partition}:eks:{region}:{account_id}:cluster/{cluster_name}"
    finding_id = (
        f"arn:{partition}:eks:{region}:{account_id}:{source}/volation/{violation_id}"
    )
    record_state = RECORDSTATE_ACTIVE
    status = "FAILED"
    description = violation["message"]
    kind = f'/{resource_violation["kind"]}' if resource_violation.get("kind") else ""
    namespace = (
        f'/{resource_violation["namespace"]}'
        if resource_violation.get("namespace")
        else ""
    )
    title = f'{cluster_name}{namespace}{kind}/{resource_violation["name"]} not compliant to policy {policy_name}'

    d = datetime.datetime.utcnow()
    new_recorded_time = d.isoformat() + "Z"

    new_finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": f"{source}-{policy_name}",
        "AwsAccountId": account_id,
        "Compliance": {"Status": status},
        "Types": [
            TYPE_PREFIX + source,
        ],
        "CreatedAt": new_recorded_time,
        "UpdatedAt": new_recorded_time,
        "Severity": {
            "Label": severity,
        },
        "Title": title,
        "Description": description,
        "ProductFields": {
            "ProviderName": source,
            "ProviderVersion": "1.0",
        },
        "Resources": [
            {
                "Id": resource_id,
                "Type": resource_type,
                "Partition": partition,
                "Region": region,
            },
        ],
        "Workflow": {"Status": "NEW"},
        "RecordState": record_state,
    }
    return new_finding

def map_gatekeeper_fields(cluster_name, group, kind, name, separator):
     join_fields = [s for s in (cluster_name, group, kind, name) if s] 
     return separator.join(join_fields)

def map_gatekeeper_violation_to_asff(cluster, constraint, violation):
    """Create a Security Hub finding based on Gatekeeper violation"""

    severity = constraint["metadata"].get("annotations", {}).get("severity", "MEDIUM")
    constraint_name = constraint["metadata"]["name"]
    resource_type = "AwsEks"
    cluster_name = cluster["clusterName"]
    account_id = cluster["accountId"]
    region = cluster["region"]
    partition = cluster["partition"]

    kind = violation.get("kind","")
    group = violation.get("group","")
    name = violation.get("name","")
    violation_id = map_gatekeeper_fields(cluster_name, group, kind, name, "-")

    resource_id = f"arn:{partition}:eks:{region}:{account_id}:cluster/{cluster_name}"
    finding_id = (
        f"arn:{partition}:eks:{region}:{account_id}:gatekeeper/violation/{constraint_name}-{violation_id}"
    )
    record_state = RECORDSTATE_ACTIVE
    status = "FAILED"
    description = violation["message"]
    resource_id = map_gatekeeper_fields(cluster_name, group, kind, name, "/")
    title = f'{resource_id} not compliant to policy {constraint_name}'

    d = datetime.datetime.utcnow()
    new_recorded_time = d.isoformat() + "Z"

    new_finding = {
        "SchemaVersion": "2018-10-08",
        "Id": finding_id,
        "ProductArn": f"arn:{partition}:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": f"Gatekeeper-{constraint_name}",
        "AwsAccountId": account_id,
        "Compliance": {"Status": status},
        "Types": [
            TYPE_PREFIX + "Gatekeeper",
        ],
        "CreatedAt": new_recorded_time,
        "UpdatedAt": new_recorded_time,
        "Severity": {
            "Label": severity,
        },
        "Title": title,
        "Description": description,
        "ProductFields": {
            "ProviderName": "Gatekeeper",
            "ProviderVersion": "1.0",
        },
        "Resources": [
            {
                "Id": resource_id,
                "Type": resource_type,
                "Partition": partition,
                "Region": region,
            },
        ],
        "Workflow": {"Status": "NEW"},
        "RecordState": record_state,
    }
    return new_finding


def parse_policy_report(api_client, cluster_info):
    """Retrieves AWS Security Hub findings based on Policy Report"""

    securityhub_findings = []
    group = "wgpolicyk8s.io"
    version = "v1alpha2"
    pretty = "true"
    api_instance = client.CustomObjectsApi(api_client)

    namespaces = client.CoreV1Api(api_client).list_namespace()
    try:
        cluster_report = api_instance.list_cluster_custom_object(
            group,
            version,
            plural="clusterpolicyreports",
            pretty=pretty,
        )
        items = cluster_report["items"]
        for namespace in namespaces.items:
            policy_report = api_instance.list_namespaced_custom_object(
                group,
                version,
                namespace.metadata.name,
                plural="policyreports",
                pretty=pretty,
            )
            items = items + policy_report["items"]
        
        for rule in items:
            for violation in rule["results"]:
                finding = map_policy_violation_to_asff(cluster_info, rule, violation)
                securityhub_findings.append(finding)
    except ApiException as e:
        logger.error("Exception when calling CustomObjectsApi->PolicyReport: %s\n" % e)

    return securityhub_findings


def parse_gatekeeper_audit_report(api_client, cluster_info):

    """Retrieves AWS Security Hub findings based on Gatekeeper audit report"""

    securityhub_findings = []
    group = "constraints.gatekeeper.sh"
    version = "v1beta1"
    pretty = "true"
    api_instance = client.CustomObjectsApi(api_client)

    try:
        api_response = api_instance.list_cluster_custom_object(
            group,
            version,
            plural="",
            pretty=pretty,
        )
        for constraint in api_response["resources"]:
            if "/status" not in constraint["name"]:
                try:
                    constraint_details = api_instance.get_cluster_custom_object(
                        group,
                        version,
                        plural=constraint["name"],
                        name="",
                    )
                    for constraint_item in constraint_details["items"]:
                        status = constraint_item["status"]
                        total_violations = status["totalViolations"]
                        violations = status["violations"]

                        for violation in violations:
                            finding = map_gatekeeper_violation_to_asff(
                                cluster_info,
                                constraint_item,
                                violation,
                            )
                            securityhub_findings.append(finding)

                        if len(violations) < total_violations:
                            logger.info(
                                f'There are violations are missing in the report ({len(violations)} out of {total_violations}), create meta-finding to notify user',
                            )
                            constraint_item["metadata"]["severity"] = "INFORMATIONAL"
                            violation = {
                                "name": "exceeded-threshold",
                                "message": "Maximum number of violations exceeded policy engine reporting threshold, you can extend limit via constraint-violations-limit flag",
                            }
                            finding = map_gatekeeper_violation_to_asff(
                                cluster_info,
                                constraint_item,
                                violation,
                            )
                            securityhub_findings.append(finding)

                except ApiException as e:
                    logger.error(
                        "Exception when calling CustomObjectsApi->contraint: %s\n" % e,
                    )

    except ApiException as e:
        logger.error(
            "Exception when calling CustomObjectsApi->list_cluster_custom_object: %s\n"
            % e,
        )
    return securityhub_findings


def lambda_handler(_event, _context):
    policy_source = os.environ["POLICY_SOURCE"]
    clusters = os.environ["CLUSTER_NAMES"].split(",")
    # Enable to run integration against all clusters
    # clusters = eks.list_clusters()["clusters"]
    lambda_function_arn_context = _context.invoked_function_arn.split(":")
    partition = aws_account_id = lambda_function_arn_context[1]
    region = aws_account_id = lambda_function_arn_context[3]
    aws_account_id = lambda_function_arn_context[4]
    cluster_info = {
        "accountId": aws_account_id,
        "region": region,
        "partition": partition,
    }
    for cluster_name in clusters:
        cluster_info["clusterName"] = cluster_name
        kubeconfig = get_kube_config(cluster_name)
        api_client = config.new_client_from_config_dict(config_dict=kubeconfig)
        # Enable to debug Kubernetes requests
        # api_client.configuration.debug = True

        if policy_source == "gatekeeper":
            securityhub_findings = parse_gatekeeper_audit_report(
                api_client,
                cluster_info,
            )
            import_new_findings(securityhub_findings)
            archive_past_violations("gatekeeper", securityhub_findings)

        else:
            securityhub_findings = parse_policy_report(api_client, cluster_info)
            import_new_findings(securityhub_findings)
            archive_past_violations("", securityhub_findings)


if __name__ == "__main__":
    lambda_handler(None, None)
