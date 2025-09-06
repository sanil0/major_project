from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Optional, Tuple

import boto3

from .config import AWS_REGION, TARGET_PRIVATE_IP, MONITORED_PORTS
from .utils import log_info, log_warn, log_error


@dataclass
class Offender:
    source_ip: str
    connections_per_min: int
    packets: int
    bytes: int


class FlowLogsDetector:
    def __init__(self, log_group_name: Optional[str] = None) -> None:
        self._logs = boto3.client("logs", region_name=AWS_REGION)
        self._ec2 = boto3.client("ec2", region_name=AWS_REGION)
        self._log_group_name = log_group_name or self._discover_log_group_name()
        log_info(f"Using VPC Flow Logs group: {self._log_group_name}")

    def _discover_log_group_name(self) -> str:
        # Try to find VPC flow logs delivering to CloudWatch for the VPC
        resp = self._ec2.describe_flow_logs()
        for fl in resp.get("FlowLogs", []):
            lg = fl.get("LogGroupName")
            if lg:
                return lg
        raise RuntimeError("Unable to auto-discover VPC Flow Logs log group. Set LOG_GROUP_NAME explicitly.")

    def _build_query(self, minutes: int) -> str:
        ports_csv = ",".join(str(p) for p in MONITORED_PORTS)
        query = (
            f"fields srcAddr, dstAddr, dstPort, action, protocol, bytes, packets "
            f"| filter dstAddr='{TARGET_PRIVATE_IP}' and dstPort in [{ports_csv}] and action='ACCEPT' and protocol=6 "
            f"| stats count() as conn, sum(packets) as packets, sum(bytes) as bytes by srcAddr "
            f"| sort conn desc | limit 5000"
        )
        return query

    def query_window(self, minutes: int = 1) -> List[Dict[str, str]]:
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=minutes)
        qid = self._logs.start_query(
            logGroupName=self._log_group_name,
            startTime=int(start.timestamp()),
            endTime=int(end.timestamp()),
            queryString=self._build_query(minutes),
        )["queryId"]
        # Poll until complete
        for _ in range(60):
            res = self._logs.get_query_results(queryId=qid)
            status = res.get("status")
            if status in ("Complete", "Failed", "Cancelled"):
                return [self._result_to_dict(r) for r in res.get("results", [])]
            time.sleep(1)
        log_warn("Logs Insights query timed out; returning partial/no results")
        return []

    def _result_to_dict(self, row: List[Dict[str, str]]) -> Dict[str, str]:
        d: Dict[str, str] = {}
        for cell in row:
            d[cell.get("field")] = cell.get("value")
        return d

    def detect_offenders(self, per_ip_conn_threshold: int, unique_src_threshold: int) -> Tuple[List[Offender], Dict[str, int]]:
        rows = self.query_window(minutes=1)
        offenders: List[Offender] = []
        for r in rows:
            try:
                conn = int(r.get("conn", "0"))
                if conn >= per_ip_conn_threshold:
                    offenders.append(
                        Offender(
                            source_ip=r.get("srcAddr", ""),
                            connections_per_min=conn,
                            packets=int(r.get("packets", "0")),
                            bytes=int(r.get("bytes", "0")),
                        )
                    )
            except Exception:
                continue
        metrics = {
            "unique_sources_last_min": len(rows),
            "offenders_detected_last_min": len(offenders),
        }
        # Spike heuristic: if unique sources greatly exceeds threshold, raise metric
        if metrics["unique_sources_last_min"] >= unique_src_threshold:
            metrics["spike_alert"] = 1
        else:
            metrics["spike_alert"] = 0
        return offenders, metrics