from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from .config import (
    AWS_REGION,
    TARGET_INSTANCE_ID,
    ALLOW_RULE_START,
    ALLOW_RULE_END,
    DENY_RULE_START,
    DENY_RULE_END,
)
from .utils import log_info, log_warn, log_error


@dataclass
class NaclAssociation:
    network_acl_id: str
    subnet_id: str


class NetworkAclManager:
    def __init__(self, dry_run: bool = False) -> None:
        self._ec2 = boto3.client("ec2", region_name=AWS_REGION)
        self._dry_run = dry_run
        self._assoc: Optional[NaclAssociation] = None

    def discover_for_instance(self, instance_id: str = TARGET_INSTANCE_ID) -> NaclAssociation:
        if self._assoc is not None:
            return self._assoc
        reservations = self._ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
        if not reservations or not reservations[0]["Instances"]:
            raise RuntimeError(f"Instance not found: {instance_id}")
        instance = reservations[0]["Instances"][0]
        subnet_id = instance["SubnetId"]
        # Find the NACL associated with this subnet
        nacls = self._ec2.describe_network_acls(
            Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]
        )["NetworkAcls"]
        if not nacls:
            raise RuntimeError(f"No Network ACL associated with subnet {subnet_id}")
        nacl_id = nacls[0]["NetworkAclId"]
        self._assoc = NaclAssociation(network_acl_id=nacl_id, subnet_id=subnet_id)
        log_info(f"Discovered NACL {nacl_id} for subnet {subnet_id}")
        return self._assoc

    def _list_entries(self, egress: bool = False) -> List[Dict]:
        assoc = self.discover_for_instance()
        nacl = self._ec2.describe_network_acls(NetworkAclIds=[assoc.network_acl_id])["NetworkAcls"][0]
        entries = [e for e in nacl["Entries"] if e["Egress"] is egress]
        return entries

    def _used_rule_numbers(self, start: int, end: int) -> List[int]:
        used = []
        for e in self._list_entries(egress=False):
            if start <= e["RuleNumber"] <= end:
                used.append(e["RuleNumber"])
        return sorted(set(used))

    def _allocate_rule_numbers(self, count: int, start: int, end: int) -> List[int]:
        used = set(self._used_rule_numbers(start, end))
        allocated: List[int] = []
        for rule in range(start, end + 1):
            if rule in used:
                continue
            allocated.append(rule)
            if len(allocated) == count:
                return allocated
        raise RuntimeError("Exhausted available rule numbers in the configured range")

    def ensure_allowlist(self, ip_cidrs: List[str], ports: List[int]) -> None:
        assoc = self.discover_for_instance()
        # Build set for quick duplicate detection
        existing = self._list_entries(egress=False)
        existing_tuples = set()
        for e in existing:
            if e.get("RuleAction", "") != "allow":
                continue
            if e.get("Protocol") != "6":
                continue
            cidr = e.get("CidrBlock")
            port_range = e.get("PortRange") or {}
            from_port = port_range.get("From")
            to_port = port_range.get("To")
            if from_port is None or to_port is None:
                continue
            existing_tuples.add((cidr, int(from_port)))
        to_create: List[Tuple[str, int]] = []
        for cidr in ip_cidrs:
            for port in ports:
                if (cidr, port) not in existing_tuples:
                    to_create.append((cidr, port))
        if not to_create:
            log_info("Allowlist already up to date")
            return
        rule_numbers = self._allocate_rule_numbers(len(to_create), ALLOW_RULE_START, ALLOW_RULE_END)
        for (cidr, port), rule_number in zip(to_create, rule_numbers):
            log_info(f"ALLOW {cidr} tcp/{port} via rule {rule_number}")
            if self._dry_run:
                continue
            try:
                self._ec2.create_network_acl_entry(
                    NetworkAclId=assoc.network_acl_id,
                    RuleNumber=rule_number,
                    Protocol="6",
                    RuleAction="allow",
                    Egress=False,
                    CidrBlock=cidr,
                    PortRange={"From": port, "To": port},
                )
            except ClientError as e:
                # If exists, replace to be idempotent
                if e.response.get("Error", {}).get("Code") == "NetworkAclEntryAlreadyExists":
                    self._ec2.replace_network_acl_entry(
                        NetworkAclId=assoc.network_acl_id,
                        RuleNumber=rule_number,
                        Protocol="6",
                        RuleAction="allow",
                        Egress=False,
                        CidrBlock=cidr,
                        PortRange={"From": port, "To": port},
                    )
                else:
                    raise

    def add_deny(self, src_ip: str, ports: List[int]) -> List[int]:
        assoc = self.discover_for_instance()
        rule_numbers = self._allocate_rule_numbers(len(ports), DENY_RULE_START, DENY_RULE_END)
        created: List[int] = []
        for port, rule_number in zip(ports, rule_numbers):
            log_warn(f"DENY {src_ip} tcp/{port} via rule {rule_number}")
            if self._dry_run:
                created.append(rule_number)
                continue
            self._ec2.create_network_acl_entry(
                NetworkAclId=assoc.network_acl_id,
                RuleNumber=rule_number,
                Protocol="6",
                RuleAction="deny",
                Egress=False,
                CidrBlock=f"{src_ip}/32",
                PortRange={"From": port, "To": port},
            )
            created.append(rule_number)
        return created

    def remove_deny_for_ip(self, src_ip: str, ports: Optional[List[int]] = None) -> List[int]:
        assoc = self.discover_for_instance()
        entries = self._list_entries(egress=False)
        removed: List[int] = []
        for e in entries:
            if e.get("RuleAction") != "deny":
                continue
            if e.get("Protocol") != "6":
                continue
            if e.get("CidrBlock") != f"{src_ip}/32":
                continue
            port_range = e.get("PortRange") or {}
            from_port = int(port_range.get("From", -1))
            if ports is not None and from_port not in ports:
                continue
            rule_number = int(e.get("RuleNumber"))
            if DENY_RULE_START <= rule_number <= DENY_RULE_END:
                log_info(f"Removing deny rule {rule_number} for {src_ip}")
                if not self._dry_run:
                    self._ec2.delete_network_acl_entry(
                        NetworkAclId=assoc.network_acl_id,
                        RuleNumber=rule_number,
                        Egress=False,
                    )
                removed.append(rule_number)
        return removed

    def cleanup_all_managed_rules(self) -> List[int]:
        assoc = self.discover_for_instance()
        entries = self._list_entries(egress=False)
        removed: List[int] = []
        for e in entries:
            rn = int(e["RuleNumber"])
            if (ALLOW_RULE_START <= rn <= ALLOW_RULE_END) or (DENY_RULE_START <= rn <= DENY_RULE_END):
                log_info(f"Removing managed rule {rn}")
                if not self._dry_run:
                    try:
                        self._ec2.delete_network_acl_entry(
                            NetworkAclId=assoc.network_acl_id,
                            RuleNumber=rn,
                            Egress=False,
                        )
                    except ClientError as exc:
                        log_warn(f"Could not remove rule {rn}: {exc}")
                removed.append(rn)
        return removed