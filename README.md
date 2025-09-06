# Intelligent DDoS Detection and Mitigation System for Cloud Applications

Secures a webapp on AWS by detecting HTTP/HTTPS DDoS patterns via VPC Flow Logs and dynamically applying Network ACL (NACL) rules to block malicious sources. Includes a Flask dashboard to view metrics and blocked IPs.

- Target webapp: `http://44.200.85.66` (ports 80/443), private IP `10.0.0.5`
- EC2 instance: `i-02fdd343671fbf558`
- VPC: `vpc-08678fdd62e6bbc2d`

## Setup

1. Python 3.10+. Install deps:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

2. Configure `ddos_guard/config.py` (region, IDs, allowlist IPs). Ensure VPC Flow Logs deliver to CloudWatch Logs.

## Run

- Dry run, single check:

```bash
python -m ddos_guard.main --dry-run --once --no-dashboard
```

- Continuous with dashboard:

```bash
python -m ddos_guard.main
```

Dashboard: `http://127.0.0.1:5000/`

## IAM Permissions

- ec2:DescribeInstances, DescribeNetworkAcls, DescribeSubnets, DescribeVpcs, DescribeFlowLogs
- ec2:CreateNetworkAclEntry, ReplaceNetworkAclEntry, DeleteNetworkAclEntry
- logs:StartQuery, GetQueryResults, StopQuery

Scope these to your VPC, subnet, and log group.
