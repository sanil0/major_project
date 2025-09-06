# Intelligent DDoS Detection and Mitigation System for Cloud Applications

This project detects potential HTTP/HTTPS DDoS activity against a web application hosted on AWS and mitigates malicious sources by dynamically updating Network ACL (NACL) rules. It also provides a Flask dashboard to view recent traffic metrics and blocked IPs.

- Target webapp: `http://44.200.85.66` (ports 80/443), private IP `10.0.0.5`
- EC2 instance: `i-02fdd343671fbf558`
- VPC: `vpc-08678fdd62e6bbc2d`

## Requirements

- AWS account with appropriate IAM permissions (ideally attach an instance profile/role if running on EC2)
- VPC Flow Logs enabled for the VPC or subnet containing the target EC2 instance, delivered to CloudWatch Logs
- Python 3.10+

### AWS Permissions

The runtime needs the following AWS IAM permissions (scoped to your resources):

- ec2:DescribeInstances
- ec2:DescribeNetworkAcls
- ec2:DescribeSubnets
- ec2:DescribeVpcs
- ec2:ReplaceNetworkAclEntry
- ec2:CreateNetworkAclEntry
- ec2:DeleteNetworkAclEntry
- ec2:DescribeFlowLogs
- logs:StartQuery
- logs:GetQueryResults
- logs:StopQuery

You can grant least-privilege by limiting ARNs to your VPC, subnet, and log group.

## How It Works

1. Discovers the target instance, subnet, and associated Network ACL in VPC `vpc-08678fdd62e6bbc2d`.
2. Periodically queries VPC Flow Logs (via CloudWatch Logs Insights) for HTTP/HTTPS traffic to the instance.
3. Detects suspicious sources (per-IP rates above thresholds or large coordinated spikes).
4. Automatically inserts NACL deny rules for those source IPs on ports 80/443 while ensuring allowlist IPs are explicitly permitted.
5. Serves a Flask dashboard exposing current metrics and the blocked list.

Behavioral expectations:
- Without `main.py` running and no DDoS: site remains accessible to everyone.
- Without `main.py` running during a DDoS: site may become inaccessible (unmitigated attack).
- With `main.py` running: your allowlisted IP can access; malicious sources are blocked by NACL; dashboard shows metrics and blocks.

## Quick Start

1. Install dependencies:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

2. Configure `ddos_guard/config.py` with your parameters (VPC ID, instance ID, region, allowlist IPs, etc.).

3. Ensure VPC Flow Logs are enabled for your VPC and delivered to CloudWatch Logs. If you dont
