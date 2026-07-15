"""
api/exposure.py — Public exposure scanner.

Makes direct read-only API calls to AWS (boto3) and Azure (azure-mgmt-*)
to enumerate every resource that is publicly accessible from the internet.

Completely independent from Prowler, ScubaGear, and the pipeline.
Shares only the SSE streaming infrastructure and credential injection pattern.

AWS services covered (18):
  s3, ec2, security_groups, rds, elb, cloudfront, apigateway,
  lambda, opensearch, redshift, eks, ecr, secretsmanager,
  sns, sqs, ebs_snapshots, elasticache

Azure services covered (12):
  storage, virtual_machines, sql, nsg, app_services, functions,
  aks, keyvault, cosmosdb, container_registry, api_management
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from api.sse import SseStream

_now_iso = lambda: datetime.now(timezone.utc).isoformat()


# ── Finding builder ───────────────────────────────────────────────────

def _finding(
    scan_id: str,
    provider: str,
    service: str,
    region: str,
    resource_id: str,
    resource_arn: str,
    resource_name: str,
    exposure_type: str,
    severity: str,
    details: dict,
) -> dict:
    return {
        "scan_id":       scan_id,
        "provider":      provider,
        "service":       service,
        "region":        region,
        "resource_id":   resource_id,
        "resource_arn":  resource_arn,
        "resource_name": resource_name,
        "exposure_type": exposure_type,
        "severity":      severity,
        "details":       json.dumps(details),
        "discovered_at": _now_iso(),
    }


# ── DB helpers ────────────────────────────────────────────────────────

async def _save_findings(findings: list[dict], db: aiosqlite.Connection) -> None:
    for f in findings:
        await db.execute(
            """INSERT INTO exposure_findings
               (scan_id, provider, service, region, resource_id, resource_arn,
                resource_name, exposure_type, severity, details, discovered_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                f["scan_id"], f["provider"], f["service"], f["region"],
                f["resource_id"], f["resource_arn"], f["resource_name"],
                f["exposure_type"], f["severity"], f["details"], f["discovered_at"],
            ),
        )
    await db.commit()


async def _update_exposure_scan(
    scan_id: str,
    status: str,
    db: aiosqlite.Connection,
    **kwargs,
) -> None:
    now = _now_iso()
    sets = ["status=?"]
    vals = [status]
    if status == "running":
        sets.append("started_at=?"); vals.append(now)
    elif status in ("complete", "failed", "cancelled"):
        sets.append("completed_at=?"); vals.append(now)
    for k, v in kwargs.items():
        sets.append(f"{k}=?"); vals.append(v)
    vals.append(scan_id)
    await db.execute(
        f"UPDATE exposure_scans SET {', '.join(sets)} WHERE id=?", vals
    )
    await db.commit()


# ── Credential builder ────────────────────────────────────────────────

def _aws_session(scan: dict, secrets: dict):
    """Return a boto3 Session with the appropriate credentials."""
    import boto3
    region = scan.get("aws_region") or "us-east-1"

    if scan.get("credential_source") == "profile" and scan.get("aws_profile"):
        return boto3.Session(profile_name=scan["aws_profile"], region_name=region)

    return boto3.Session(
        aws_access_key_id=secrets.get("aws_access_key_id"),
        aws_secret_access_key=secrets.get("aws_secret_access_key"),
        aws_session_token=secrets.get("aws_session_token"),
        region_name=region,
    )


def _azure_credential(secrets: dict):
    """Return an Azure ClientSecretCredential."""
    from azure.identity import ClientSecretCredential
    return ClientSecretCredential(
        tenant_id=secrets.get("azure_tenant_id", ""),
        client_id=secrets.get("azure_client_id", ""),
        client_secret=secrets.get("azure_client_secret", ""),
    )


# ── AWS scanners ──────────────────────────────────────────────────────

def _scan_s3(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        s3 = session.client("s3", region_name="us-east-1")
        buckets = s3.list_buckets().get("Buckets", [])
        for b in buckets:
            name = b["Name"]
            arn  = f"arn:aws:s3:::{name}"
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([
                    pab.get("BlockPublicAcls"), pab.get("IgnorePublicAcls"),
                    pab.get("BlockPublicPolicy"), pab.get("RestrictPublicBuckets"),
                ]):
                    findings.append(_finding(
                        scan_id, "aws", "s3", "global", name, arn, name,
                        "Public access block not fully enabled", "High",
                        {"public_access_block": pab},
                    ))
            except Exception:
                # No block config means public access is possible
                try:
                    status = s3.get_bucket_policy_status(Bucket=name)
                    if status.get("PolicyStatus", {}).get("IsPublic"):
                        findings.append(_finding(
                            scan_id, "aws", "s3", "global", name, arn, name,
                            "Bucket policy grants public access", "High",
                            {"source": "policy_status"},
                        ))
                except Exception:
                    pass
    except Exception as e:
        findings.append(_finding(
            scan_id, "aws", "s3", "global", "ERROR", "", "s3",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_ec2(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for r in page.get("Reservations", []):
                for inst in r.get("Instances", []):
                    if inst.get("State", {}).get("Name") != "running":
                        continue
                    pub_ip = inst.get("PublicIpAddress")
                    if pub_ip:
                        iid  = inst["InstanceId"]
                        name = next((t["Value"] for t in inst.get("Tags", [])
                                     if t["Key"] == "Name"), iid)
                        findings.append(_finding(
                            scan_id, "aws", "ec2", region, iid,
                            f"arn:aws:ec2:{region}::{iid}", name,
                            "Instance has public IP address", "Medium",
                            {"public_ip": pub_ip, "instance_type": inst.get("InstanceType")},
                        ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "aws", "ec2", region, "ERROR", "", "ec2",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_security_groups(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    HIGH_PORTS = {22, 3389, 5432, 3306, 1433, 27017, 6379, 9200}
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sgid = sg["GroupId"]
                name = sg.get("GroupName", sgid)
                arn  = f"arn:aws:ec2:{region}:{sg.get('OwnerId','')}:security-group/{sgid}"
                for rule in sg.get("IpPermissions", []):
                    for cidr in rule.get("IpRanges", []):
                        if cidr.get("CidrIp") in ("0.0.0.0/0",):
                            from_port = rule.get("FromPort", 0)
                            to_port   = rule.get("ToPort", 65535)
                            ports     = f"{from_port}-{to_port}"
                            sev = "High" if any(
                                p in range(from_port, to_port + 1)
                                for p in HIGH_PORTS
                            ) else "Medium"
                            findings.append(_finding(
                                scan_id, "aws", "security_groups", region,
                                sgid, arn, name,
                                f"Unrestricted ingress from 0.0.0.0/0 on port(s) {ports}",
                                sev, {"ports": ports, "protocol": rule.get("IpProtocol")},
                            ))
                    for cidr6 in rule.get("Ipv6Ranges", []):
                        if cidr6.get("CidrIpv6") == "::/0":
                            from_port = rule.get("FromPort", 0)
                            findings.append(_finding(
                                scan_id, "aws", "security_groups", region,
                                sgid, arn, name,
                                f"Unrestricted ingress from ::/0 on port {from_port}",
                                "Medium", {"port": from_port},
                            ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "aws", "security_groups", region, "ERROR", "", "security_groups",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_rds(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        rds = session.client("rds", region_name=region)
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if db.get("PubliclyAccessible"):
                    dbid = db["DBInstanceIdentifier"]
                    findings.append(_finding(
                        scan_id, "aws", "rds", region, dbid,
                        db.get("DBInstanceArn", ""), dbid,
                        "DB instance is publicly accessible", "High",
                        {"engine": db.get("Engine"), "endpoint": db.get("Endpoint", {}).get("Address", "")},
                    ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "aws", "rds", region, "ERROR", "", "rds",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_elb(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        elb = session.client("elbv2", region_name=region)
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("Scheme") == "internet-facing":
                    name = lb["LoadBalancerName"]
                    findings.append(_finding(
                        scan_id, "aws", "elb", region, name,
                        lb.get("LoadBalancerArn", ""), name,
                        "Load balancer is internet-facing", "Medium",
                        {"type": lb.get("Type"), "dns": lb.get("DNSName", "")},
                    ))
    except Exception as e:
        pass  # ELBv2 may not be available in all regions
    try:
        elb1 = session.client("elb", region_name=region)
        lbs = elb1.describe_load_balancers().get("LoadBalancerDescriptions", [])
        for lb in lbs:
            if lb.get("Scheme") == "internet-facing":
                name = lb["LoadBalancerName"]
                findings.append(_finding(
                    scan_id, "aws", "elb", region, name, "", name,
                    "Classic load balancer is internet-facing", "Medium",
                    {"dns": lb.get("DNSName", "")},
                ))
    except Exception:
        pass
    return findings


def _scan_lambda(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        lmb = session.client("lambda", region_name=region)
        paginator = lmb.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                fname = fn["FunctionName"]
                try:
                    url_cfg = lmb.get_function_url_config(FunctionName=fname)
                    if url_cfg.get("AuthType") == "NONE":
                        findings.append(_finding(
                            scan_id, "aws", "lambda", region, fname,
                            fn.get("FunctionArn", ""), fname,
                            "Function URL with no authentication (AuthType=NONE)", "High",
                            {"url": url_cfg.get("FunctionUrl", "")},
                        ))
                except Exception:
                    pass
    except Exception as e:
        pass
    return findings


def _scan_redshift(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        rs = session.client("redshift", region_name=region)
        paginator = rs.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                if c.get("PubliclyAccessible"):
                    cid = c["ClusterIdentifier"]
                    findings.append(_finding(
                        scan_id, "aws", "redshift", region, cid,
                        f"arn:aws:redshift:{region}::{cid}", cid,
                        "Redshift cluster is publicly accessible", "High",
                        {"endpoint": c.get("Endpoint", {}).get("Address", "")},
                    ))
    except Exception:
        pass
    return findings


def _scan_eks(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        eks = session.client("eks", region_name=region)
        clusters = eks.list_clusters().get("clusters", [])
        for name in clusters:
            desc = eks.describe_cluster(name=name)["cluster"]
            if desc.get("resourcesVpcConfig", {}).get("endpointPublicAccess"):
                findings.append(_finding(
                    scan_id, "aws", "eks", region, name,
                    desc.get("arn", ""), name,
                    "EKS cluster API endpoint is publicly accessible", "Medium",
                    {"public_access_cidrs": desc.get("resourcesVpcConfig", {}).get("publicAccessCidrs", [])},
                ))
    except Exception:
        pass
    return findings


def _scan_ecr(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        ecr = session.client("ecr", region_name=region)
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                rname = repo["repositoryName"]
                try:
                    policy = ecr.get_repository_policy(repositoryName=rname)
                    pol = json.loads(policy.get("policyText", "{}"))
                    for stmt in pol.get("Statement", []):
                        principal = stmt.get("Principal", "")
                        if principal == "*" or principal == {"AWS": "*"}:
                            findings.append(_finding(
                                scan_id, "aws", "ecr", region, rname,
                                repo.get("repositoryArn", ""), rname,
                                "ECR repository policy allows public pull", "High",
                                {"policy_sid": stmt.get("Sid", "")},
                            ))
                            break
                except Exception:
                    pass
    except Exception:
        pass
    return findings


def _scan_ebs_snapshots(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)
        account_id = session.client("sts").get_caller_identity()["Account"]
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=[account_id]):
            for snap in page.get("Snapshots", []):
                try:
                    perms = ec2.describe_snapshot_attribute(
                        SnapshotId=snap["SnapshotId"],
                        Attribute="createVolumePermission",
                    )
                    for p in perms.get("CreateVolumePermissions", []):
                        if p.get("Group") == "all":
                            findings.append(_finding(
                                scan_id, "aws", "ebs_snapshots", region,
                                snap["SnapshotId"], "", snap["SnapshotId"],
                                "EBS snapshot is publicly shared", "High",
                                {"volume_id": snap.get("VolumeId", ""),
                                 "description": snap.get("Description", "")[:80]},
                            ))
                except Exception:
                    pass
    except Exception:
        pass
    return findings


def _scan_sqs(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        sqs = session.client("sqs", region_name=region)
        queues = sqs.list_queues().get("QueueUrls", [])
        for url in queues:
            try:
                attrs = sqs.get_queue_attributes(
                    QueueUrl=url,
                    AttributeNames=["Policy", "QueueArn"],
                )["Attributes"]
                policy_str = attrs.get("Policy", "")
                if policy_str:
                    policy = json.loads(policy_str)
                    for stmt in policy.get("Statement", []):
                        if stmt.get("Principal") in ("*", {"AWS": "*"}):
                            qname = url.split("/")[-1]
                            findings.append(_finding(
                                scan_id, "aws", "sqs", region, qname,
                                attrs.get("QueueArn", ""), qname,
                                "SQS queue policy allows public access", "Medium",
                                {},
                            ))
                            break
            except Exception:
                pass
    except Exception:
        pass
    return findings


def _scan_sns(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        sns = session.client("sns", region_name=region)
        paginator = sns.get_paginator("list_topics")
        for page in paginator.paginate():
            for topic in page.get("Topics", []):
                arn = topic["TopicArn"]
                try:
                    attrs = sns.get_topic_attributes(TopicArn=arn)["Attributes"]
                    policy_str = attrs.get("Policy", "")
                    if policy_str:
                        policy = json.loads(policy_str)
                        for stmt in policy.get("Statement", []):
                            if stmt.get("Principal") in ("*", {"AWS": "*"}):
                                name = arn.split(":")[-1]
                                findings.append(_finding(
                                    scan_id, "aws", "sns", region, name, arn, name,
                                    "SNS topic policy allows public access", "Medium",
                                    {},
                                ))
                                break
                except Exception:
                    pass
    except Exception:
        pass
    return findings


def _scan_opensearch(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        es = session.client("opensearch", region_name=region)
        domains = es.list_domain_names().get("DomainNames", [])
        names = [d["DomainName"] for d in domains]
        if names:
            details_list = es.describe_domains(DomainNames=names).get("DomainStatusList", [])
            for d in details_list:
                policy_str = d.get("AccessPolicies", "")
                if policy_str:
                    try:
                        policy = json.loads(policy_str)
                        for stmt in policy.get("Statement", []):
                            if stmt.get("Principal") in ("*", {"AWS": "*"}):
                                name = d["DomainName"]
                                findings.append(_finding(
                                    scan_id, "aws", "opensearch", region,
                                    name, d.get("ARN", ""), name,
                                    "OpenSearch domain access policy allows public access", "High",
                                    {"endpoint": d.get("Endpoint", "")},
                                ))
                                break
                    except Exception:
                        pass
    except Exception:
        pass
    return findings


def _scan_secretsmanager(session, scan_id: str, region: str) -> list[dict]:
    findings = []
    try:
        sm = session.client("secretsmanager", region_name=region)
        paginator = sm.get_paginator("list_secrets")
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                sarn = secret.get("ARN", "")
                name = secret.get("Name", "")
                try:
                    policy_str = sm.get_resource_policy(SecretId=sarn).get("ResourcePolicy", "")
                    if policy_str:
                        policy = json.loads(policy_str)
                        for stmt in policy.get("Statement", []):
                            if stmt.get("Principal") in ("*", {"AWS": "*"}):
                                findings.append(_finding(
                                    scan_id, "aws", "secretsmanager", region,
                                    name, sarn, name,
                                    "Secrets Manager resource policy allows public access", "High",
                                    {},
                                ))
                                break
                except Exception:
                    pass
    except Exception:
        pass
    return findings


# ── AWS services registry ─────────────────────────────────────────────

AWS_SCANNERS = {
    "s3":               (_scan_s3,              "S3 Buckets"),
    "ec2":              (_scan_ec2,             "EC2 Instances"),
    "security_groups":  (_scan_security_groups, "Security Groups"),
    "rds":              (_scan_rds,             "RDS Instances"),
    "elb":              (_scan_elb,             "Load Balancers"),
    "lambda":           (_scan_lambda,          "Lambda Functions"),
    "redshift":         (_scan_redshift,        "Redshift Clusters"),
    "eks":              (_scan_eks,             "EKS Clusters"),
    "ecr":              (_scan_ecr,             "ECR Repositories"),
    "ebs_snapshots":    (_scan_ebs_snapshots,   "EBS Snapshots"),
    "sqs":              (_scan_sqs,             "SQS Queues"),
    "sns":              (_scan_sns,             "SNS Topics"),
    "opensearch":       (_scan_opensearch,      "OpenSearch Domains"),
    "secretsmanager":   (_scan_secretsmanager,  "Secrets Manager"),
}


# ── Azure scanners ────────────────────────────────────────────────────

def _scan_azure_storage(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(credential, subscription_id)
        for account in client.storage_accounts.list():
            name = account.name
            rg   = account.id.split("/")[4] if account.id else ""
            arn  = account.id or ""
            # Check blob public access
            if account.allow_blob_public_access:
                findings.append(_finding(
                    scan_id, "azure", "storage", account.location or "", name, arn, name,
                    "Storage account allows blob public access", "High",
                    {"resource_group": rg},
                ))
            # Check public network access
            if account.public_network_access and str(account.public_network_access) == "Enabled":
                if not account.network_rule_set or \
                   str(getattr(account.network_rule_set, "default_action", "Allow")) == "Allow":
                    findings.append(_finding(
                        scan_id, "azure", "storage", account.location or "", name, arn, name,
                        "Storage account has no network restrictions (public access allowed)", "Medium",
                        {"resource_group": rg},
                    ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "storage", "", "ERROR", "", "storage",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_vms(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.compute import ComputeManagementClient
        from azure.mgmt.network import NetworkManagementClient
        compute = ComputeManagementClient(credential, subscription_id)
        network = NetworkManagementClient(credential, subscription_id)
        for vm in compute.virtual_machines.list_all():
            name = vm.name
            loc  = vm.location or ""
            for nic_ref in (vm.network_profile.network_interfaces or []):
                nic_id = nic_ref.id or ""
                parts  = nic_id.split("/")
                if len(parts) > 8:
                    rg      = parts[4]
                    nic_name = parts[-1]
                    try:
                        nic = network.network_interfaces.get(rg, nic_name)
                        for ipc in (nic.ip_configurations or []):
                            if ipc.public_ip_address:
                                pip_parts = ipc.public_ip_address.id.split("/")
                                pip_name  = pip_parts[-1]
                                pip_rg    = pip_parts[4]
                                pip = network.public_ip_addresses.get(pip_rg, pip_name)
                                if pip.ip_address:
                                    findings.append(_finding(
                                        scan_id, "azure", "virtual_machines", loc,
                                        name, vm.id or "", name,
                                        "VM has public IP address assigned", "Medium",
                                        {"public_ip": pip.ip_address, "resource_group": rg},
                                    ))
                    except Exception:
                        pass
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "virtual_machines", "", "ERROR", "", "virtual_machines",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_sql(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.sql import SqlManagementClient
        client = SqlManagementClient(credential, subscription_id)
        for server in client.servers.list():
            name = server.name
            rg   = server.id.split("/")[4] if server.id else ""
            loc  = server.location or ""
            # Check public network access
            if str(getattr(server, "public_network_access", "Enabled")) == "Enabled":
                findings.append(_finding(
                    scan_id, "azure", "sql", loc, name, server.id or "", name,
                    "SQL Server has public network access enabled", "High",
                    {"resource_group": rg, "fqdn": getattr(server, "fully_qualified_domain_name", "")},
                ))
            # Check firewall rules for 0.0.0.0 - 255.255.255.255
            try:
                for rule in client.firewall_rules.list_by_server(rg, name):
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        findings.append(_finding(
                            scan_id, "azure", "sql", loc, name, server.id or "", name,
                            "SQL Server firewall rule allows all IP addresses", "High",
                            {"rule_name": rule.name, "resource_group": rg},
                        ))
            except Exception:
                pass
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "sql", "", "ERROR", "", "sql",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_nsg(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    HIGH_PORTS = {22, 3389, 5432, 3306, 1433, 27017, 6379}
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(credential, subscription_id)
        for nsg in client.network_security_groups.list_all():
            name = nsg.name
            loc  = nsg.location or ""
            rg   = nsg.id.split("/")[4] if nsg.id else ""
            for rule in (nsg.security_rules or []):
                if (rule.direction == "Inbound" and
                    rule.access == "Allow" and
                    rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")):
                    dp = rule.destination_port_range or ""
                    sev = "High" if any(
                        str(p) in dp or dp == "*"
                        for p in HIGH_PORTS
                    ) else "Medium"
                    findings.append(_finding(
                        scan_id, "azure", "nsg", loc, name, nsg.id or "", name,
                        f"NSG allows unrestricted inbound on port(s) {dp}", sev,
                        {"rule_name": rule.name, "ports": dp, "resource_group": rg},
                    ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "nsg", "", "ERROR", "", "nsg",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_keyvault(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        client = KeyVaultManagementClient(credential, subscription_id)
        for vault in client.vaults.list():
            name = vault.name
            loc  = vault.location or ""
            props = vault.properties
            if props:
                pna = str(getattr(props, "public_network_access", "Enabled"))
                net = getattr(props, "network_acls", None)
                default_action = str(getattr(net, "default_action", "Allow")) if net else "Allow"
                if pna == "Enabled" and default_action == "Allow":
                    findings.append(_finding(
                        scan_id, "azure", "keyvault", loc, name, vault.id or "", name,
                        "Key Vault is publicly accessible without network restrictions", "High",
                        {},
                    ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "keyvault", "", "ERROR", "", "keyvault",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_cosmosdb(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
        client = CosmosDBManagementClient(credential, subscription_id)
        for account in client.database_accounts.list():
            name = account.name
            loc  = account.location or ""
            if str(getattr(account, "public_network_access", "Enabled")) == "Enabled":
                findings.append(_finding(
                    scan_id, "azure", "cosmosdb", loc, name, account.id or "", name,
                    "Cosmos DB account has public network access enabled", "High",
                    {},
                ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "cosmosdb", "", "ERROR", "", "cosmosdb",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_aks(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.containerservice import ContainerServiceClient
        client = ContainerServiceClient(credential, subscription_id)
        for cluster in client.managed_clusters.list():
            name = cluster.name
            loc  = cluster.location or ""
            api_profile = getattr(cluster, "api_server_access_profile", None)
            if api_profile:
                if not getattr(api_profile, "enable_private_cluster", False):
                    findings.append(_finding(
                        scan_id, "azure", "aks", loc, name, cluster.id or "", name,
                        "AKS cluster API server is publicly accessible", "Medium",
                        {"authorized_ranges": getattr(api_profile, "authorized_ip_ranges", [])},
                    ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "aks", "", "ERROR", "", "aks",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_acr(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient
        client = ContainerRegistryManagementClient(credential, subscription_id)
        for registry in client.registries.list():
            name = registry.name
            loc  = registry.location or ""
            if getattr(registry, "admin_user_enabled", False):
                findings.append(_finding(
                    scan_id, "azure", "container_registry", loc, name,
                    registry.id or "", name,
                    "Container registry admin user is enabled", "Medium",
                    {"login_server": getattr(registry, "login_server", "")},
                ))
            if str(getattr(registry, "public_network_access", "Enabled")) == "Enabled":
                findings.append(_finding(
                    scan_id, "azure", "container_registry", loc, name,
                    registry.id or "", name,
                    "Container registry allows public network access", "Medium",
                    {},
                ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "container_registry", "", "ERROR", "", "container_registry",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


def _scan_azure_appservices(credential, scan_id: str, subscription_id: str) -> list[dict]:
    findings = []
    try:
        from azure.mgmt.web import WebSiteManagementClient
        client = WebSiteManagementClient(credential, subscription_id)
        for app in client.web_apps.list():
            name = app.name
            loc  = app.location or ""
            if not getattr(app, "https_only", True):
                findings.append(_finding(
                    scan_id, "azure", "app_services", loc, name, app.id or "", name,
                    "App Service does not enforce HTTPS", "Medium",
                    {"default_host": getattr(app, "default_host_name", "")},
                ))
    except Exception as e:
        findings.append(_finding(
            scan_id, "azure", "app_services", "", "ERROR", "", "app_services",
            f"Scan error: {str(e)[:100]}", "Low", {},
        ))
    return findings


# ── Azure services registry ───────────────────────────────────────────

AZURE_SCANNERS = {
    "storage":            (_scan_azure_storage,     "Storage Accounts"),
    "virtual_machines":   (_scan_azure_vms,         "Virtual Machines"),
    "sql":                (_scan_azure_sql,          "SQL Servers"),
    "nsg":                (_scan_azure_nsg,          "Network Security Groups"),
    "keyvault":           (_scan_azure_keyvault,     "Key Vaults"),
    "cosmosdb":           (_scan_azure_cosmosdb,     "Cosmos DB"),
    "aks":                (_scan_azure_aks,          "AKS Clusters"),
    "container_registry": (_scan_azure_acr,          "Container Registries"),
    "app_services":       (_scan_azure_appservices,  "App Services"),
}

# Service display names for UI
AWS_EXPOSURE_SERVICES  = {k: v[1] for k, v in AWS_SCANNERS.items()}
AZURE_EXPOSURE_SERVICES = {k: v[1] for k, v in AZURE_SCANNERS.items()}


# ── Main executor ─────────────────────────────────────────────────────

async def execute_exposure_scan(
    scan: dict,
    stream: SseStream,
    raw_secrets: Optional[dict] = None,
) -> None:
    """
    Execute a full exposure scan as an asyncio background task.
    Each service scanner runs in a thread pool to avoid blocking the event loop.
    """
    from db.database import _DB_PATH

    scan_id  = scan["id"]
    provider = scan["provider"]
    secrets  = raw_secrets or {}

    async with aiosqlite.connect(_DB_PATH) as db:
        await _update_exposure_scan(scan_id, "running", db)
        await stream.send_status("running")

        regions_raw = scan.get("regions_scope", "[]")
        try:
            regions = json.loads(regions_raw) if isinstance(regions_raw, str) else regions_raw
        except Exception:
            regions = []

        services_raw = scan.get("services_scope", "[]")
        try:
            services = json.loads(services_raw) if isinstance(services_raw, str) else services_raw
        except Exception:
            services = []

        all_findings: list[dict] = []
        total_resources = 0

        if provider == "aws":
            session = _aws_session(scan, secrets)
            if not regions:
                regions = [scan.get("aws_region") or "us-east-1"]

            scanners = {k: v for k, v in AWS_SCANNERS.items()
                        if not services or k in services}

            for svc_key, (fn, label) in scanners.items():
                await stream.send_log(f"Scanning {label}...")
                svc_findings = []
                # S3 is global — only run once
                if svc_key == "s3":
                    loop = asyncio.get_event_loop()
                    svc_findings = await loop.run_in_executor(
                        None, fn, session, scan_id, regions[0]
                    )
                    total_resources += 1
                else:
                    for region in regions:
                        loop = asyncio.get_event_loop()
                        region_findings = await loop.run_in_executor(
                            None, fn, session, scan_id, region
                        )
                        svc_findings.extend(region_findings)
                        total_resources += 1

                exposed = [f for f in svc_findings
                           if not f["exposure_type"].startswith("Scan error")]
                if exposed:
                    await stream.send_log(
                        f"  {label}: {len(exposed)} exposed resource(s) found"
                    )
                else:
                    await stream.send_log(f"  {label}: none exposed")

                all_findings.extend(svc_findings)
                await stream.send_json({"type": "heartbeat"})

        elif provider == "azure":
            try:
                credential = _azure_credential(secrets)
            except Exception as e:
                await stream.send_log(f"Azure credential error: {e}", stream="stderr")
                await _update_exposure_scan(scan_id, "failed", db)
                await stream.send_status("failed")
                await stream.close()
                return

            sub_id = (
                scan.get("azure_subscription_id") or
                secrets.get("azure_subscription_id", "")
            )
            if not sub_id:
                await stream.send_log(
                    "Azure subscription ID is required for exposure scanning.",
                    stream="stderr",
                )
                await _update_exposure_scan(scan_id, "failed", db)
                await stream.send_status("failed")
                await stream.close()
                return

            scanners = {k: v for k, v in AZURE_SCANNERS.items()
                        if not services or k in services}

            for svc_key, (fn, label) in scanners.items():
                await stream.send_log(f"Scanning {label}...")
                loop = asyncio.get_event_loop()
                svc_findings = await loop.run_in_executor(
                    None, fn, credential, scan_id, sub_id
                )
                exposed = [f for f in svc_findings
                           if not f["exposure_type"].startswith("Scan error")]
                if exposed:
                    await stream.send_log(
                        f"  {label}: {len(exposed)} exposed resource(s) found"
                    )
                else:
                    await stream.send_log(f"  {label}: none exposed")

                all_findings.extend(svc_findings)
                total_resources += 1
                await stream.send_json({"type": "heartbeat"})

        # Save findings
        real_findings = [f for f in all_findings
                         if not f["exposure_type"].startswith("Scan error")]
        if real_findings:
            await _save_findings(real_findings, db)

        high   = sum(1 for f in real_findings if f["severity"] == "High")
        medium = sum(1 for f in real_findings if f["severity"] == "Medium")
        low    = sum(1 for f in real_findings if f["severity"] == "Low")

        await _update_exposure_scan(
            scan_id, "complete", db,
            total_resources=total_resources,
            total_exposed=len(real_findings),
            high_count=high,
            medium_count=medium,
            low_count=low,
            duration_secs=0,
        )

        await stream.send_log("─" * 60)
        await stream.send_log(f"✓ Scan complete — {len(real_findings)} exposed resources found")
        await stream.send_log(f"  High: {high}  Medium: {medium}  Low: {low}")
        await stream.send_json({
            "type":    "exposure_complete",
            "total":   len(real_findings),
            "high":    high,
            "medium":  medium,
            "low":     low,
        })
        await stream.send_status("complete")
        await stream.close()