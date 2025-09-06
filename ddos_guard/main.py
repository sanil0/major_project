from __future__ import annotations

import argparse
import threading
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from . import config
from .aws_nacl import NetworkAclManager
from .dashboard import create_app
from .flowlogs_detector import FlowLogsDetector
from .utils import BlockRecord, SharedState, log_info, log_warn, log_error


def run_dashboard(state: SharedState) -> None:
    app = create_app(state)
    app.run(host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)


def ensure_allowlist(nacl: NetworkAclManager, state: SharedState) -> None:
    # Normalize allowlist to CIDRs
    allowlist = []
    for ip in config.ALLOWLIST_IPS:
        if "/" in ip:
            allowlist.append(ip)
        else:
            allowlist.append(f"{ip}/32")
    nacl.ensure_allowlist(allowlist, config.MONITORED_PORTS)
    with state.lock:
        state.allowed_ips = set(ip.split("/")[0] for ip in allowlist)


def main() -> None:
    load_dotenv()

    parser = argparse.ArgumentParser(description="Intelligent DDoS Detection and Mitigation System")
    parser.add_argument("--dry-run", action="store_true", default=config.DRY_RUN_ENV_DEFAULT, help="Do not modify AWS resources")
    parser.add_argument("--no-dashboard", action="store_true", help="Disable Flask dashboard")
    parser.add_argument("--once", action="store_true", help="Run a single detection cycle and exit")
    parser.add_argument("--cleanup", action="store_true", help="Remove all managed NACL rules and exit")
    args = parser.parse_args()

    state = SharedState()

    nacl = NetworkAclManager(dry_run=args.dry_run)
    detector = FlowLogsDetector(log_group_name=config.LOG_GROUP_NAME)

    if args.cleanup:
        removed = nacl.cleanup_all_managed_rules()
        log_info(f"Removed {len(removed)} managed rules")
        return

    if not args.no_dashboard:
        t = threading.Thread(target=run_dashboard, args=(state,), daemon=True)
        t.start()
        log_info(f"Dashboard running at http://{config.DASHBOARD_HOST}:{config.DASHBOARD_PORT}")

    # Initial allowlist enforcement
    ensure_allowlist(nacl, state)

    while True:
        try:
            offenders, metrics = detector.detect_offenders(
                per_ip_conn_threshold=config.DETECTION_THRESHOLDS["per_ip_conn_threshold"],
                unique_src_threshold=config.DETECTION_THRESHOLDS["unique_src_threshold"],
            )
            state.update_metrics(metrics)

            # Block offenders
            for off in offenders:
                src_ip = off.source_ip
                if not src_ip or src_ip in state.allowed_ips:
                    continue
                if src_ip not in state.blocked:
                    nacl.add_deny(src_ip, config.MONITORED_PORTS)
                    state.add_block(
                        BlockRecord(
                            source_ip=src_ip,
                            first_blocked_at=datetime.now(timezone.utc),
                            last_seen_at=datetime.now(timezone.utc),
                            packet_rate_per_min=off.connections_per_min,
                            bytes_per_min=off.bytes,
                        )
                    )
                else:
                    state.refresh_block(src_ip, off.connections_per_min, off.bytes)

            # Expire old blocks
            expired = state.expire_blocks(config.DETECTION_THRESHOLDS["block_expire_minutes"])
            for ip in expired:
                nacl.remove_deny_for_ip(ip, config.MONITORED_PORTS)

            # Cap number of active denies
            max_denies = config.DETECTION_THRESHOLDS["max_active_denies"]
            with state.lock:
                if len(state.blocked) > max_denies:
                    # Remove oldest
                    sorted_ips = sorted(state.blocked.values(), key=lambda r: r.first_blocked_at)
                    to_remove = sorted_ips[: len(state.blocked) - max_denies]
                    for rec in to_remove:
                        nacl.remove_deny_for_ip(rec.source_ip, config.MONITORED_PORTS)
                        del state.blocked[rec.source_ip]

            log_info(f"Cycle complete: metrics={state.metrics} active_blocks={len(state.blocked)}")
        except Exception as exc:
            log_error(f"Cycle error: {exc}")

        if args.once:
            break
        time.sleep(config.DETECTOR_POLL_SECONDS)


if __name__ == "__main__":
    main()