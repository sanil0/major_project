from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Set

from rich.console import Console
from rich.table import Table

_console = Console()


def log_info(message: str) -> None:
    _console.log(f"[bold cyan]INFO[/]: {message}")


def log_warn(message: str) -> None:
    _console.log(f"[bold yellow]WARN[/]: {message}")


def log_error(message: str) -> None:
    _console.log(f"[bold red]ERROR[/]: {message}")


def pretty_table(title: str, columns: List[str], rows: List[List[str]]) -> None:
    table = Table(title=title)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*[str(c) for c in row])
    _console.print(table)


@dataclass
class BlockRecord:
    source_ip: str
    first_blocked_at: datetime
    last_seen_at: datetime
    packet_rate_per_min: int = 0
    bytes_per_min: int = 0

    def is_expired(self, expire_minutes: int) -> bool:
        if expire_minutes <= 0:
            return False
        return datetime.now(timezone.utc) - self.last_seen_at > timedelta(minutes=expire_minutes)


@dataclass
class SharedState:
    blocked: Dict[str, BlockRecord] = field(default_factory=dict)
    metrics: Dict[str, int] = field(default_factory=dict)
    allowed_ips: Set[str] = field(default_factory=set)
    lock: threading.RLock = field(default_factory=threading.RLock)

    def to_json(self) -> str:
        with self.lock:
            return json.dumps(
                {
                    "blocked": {
                        ip: {
                            "first_blocked_at": rec.first_blocked_at.isoformat(),
                            "last_seen_at": rec.last_seen_at.isoformat(),
                            "packet_rate_per_min": rec.packet_rate_per_min,
                            "bytes_per_min": rec.bytes_per_min,
                        }
                        for ip, rec in self.blocked.items()
                    },
                    "metrics": self.metrics,
                    "allowed_ips": sorted(list(self.allowed_ips)),
                }
            )

    def update_metrics(self, new_metrics: Dict[str, int]) -> None:
        with self.lock:
            self.metrics.update(new_metrics)

    def add_block(self, record: BlockRecord) -> None:
        with self.lock:
            self.blocked[record.source_ip] = record

    def refresh_block(self, source_ip: str, packet_rate_per_min: int, bytes_per_min: int) -> None:
        with self.lock:
            if source_ip in self.blocked:
                rec = self.blocked[source_ip]
                rec.last_seen_at = datetime.now(timezone.utc)
                rec.packet_rate_per_min = packet_rate_per_min
                rec.bytes_per_min = bytes_per_min

    def expire_blocks(self, expire_minutes: int) -> List[str]:
        expired: List[str] = []
        with self.lock:
            for ip, rec in list(self.blocked.items()):
                if rec.is_expired(expire_minutes):
                    expired.append(ip)
                    del self.blocked[ip]
        return expired