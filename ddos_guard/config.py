from __future__ import annotations

import os
from typing import Dict, List, Optional

# Core AWS configuration
AWS_REGION: str = os.getenv("AWS_REGION", "us-east-1")
TARGET_VPC_ID: str = os.getenv("TARGET_VPC_ID", "vpc-08678fdd62e6bbc2d")
TARGET_INSTANCE_ID: str = os.getenv("TARGET_INSTANCE_ID", "i-02fdd343671fbf558")
TARGET_PRIVATE_IP: str = os.getenv("TARGET_PRIVATE_IP", "10.0.0.5")

# Ports monitored for HTTP/HTTPS
MONITORED_PORTS: List[int] = [80, 443]

# Allowlist IPs (e.g., mobile IPs). Accepts single IPs or CIDRs.
ALLOWLIST_IPS: List[str] = [
    os.getenv("MOBILE_IP_PRIMARY", "152.57.77.167"),
    os.getenv("MOBILE_IP_SECONDARY", "152.57.48.99"),
]

# CloudWatch Logs group for VPC Flow Logs. Leave empty to auto-discover from DescribeFlowLogs.
LOG_GROUP_NAME: Optional[str] = os.getenv("LOG_GROUP_NAME", "") or None

# Detection thresholds per minute
DETECTION_THRESHOLDS: Dict[str, int] = {
    # Per source IP connection attempts per minute to monitored ports
    "per_ip_conn_threshold": int(os.getenv("PER_IP_CONN_THRESHOLD", "300")),
    # Unique source IPs per minute threshold (spike detection)
    "unique_src_threshold": int(os.getenv("UNIQUE_SRC_THRESHOLD", "1000")),
    # Maximum deny rules to keep active
    "max_active_denies": int(os.getenv("MAX_ACTIVE_DENIES", "500")),
    # Block duration in minutes before auto-expire (set 0 to never expire)
    "block_expire_minutes": int(os.getenv("BLOCK_EXPIRE_MINUTES", "180")),
}

# Rule number ranges reserved for this service
ALLOW_RULE_START: int = 1000
ALLOW_RULE_END: int = 1999
DENY_RULE_START: int = 20000
DENY_RULE_END: int = 20999

# Polling intervals
DETECTOR_POLL_SECONDS: int = int(os.getenv("DETECTOR_POLL_SECONDS", "30"))
DASHBOARD_HOST: str = os.getenv("DASHBOARD_HOST", "127.0.0.1")
DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "5000"))

# Dry-run safety: when True, no AWS modifying calls are made
DRY_RUN_ENV_DEFAULT: bool = os.getenv("DRY_RUN", "false").lower() == "true"