from __future__ import annotations

from flask import Flask, jsonify, render_template_string

from .utils import SharedState


def create_app(state: SharedState) -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        return render_template_string(
            """
            <html>
                <head><title>DDoS Guard Dashboard</title></head>
                <body>
                    <h1>DDoS Guard</h1>
                    <div>
                        <a href="/metrics">Metrics (JSON)</a> |
                        <a href="/blocked">Blocked IPs (JSON)</a>
                    </div>
                </body>
            </html>
            """
        )

    @app.get("/metrics")
    def metrics():
        return jsonify(state.metrics)

    @app.get("/blocked")
    def blocked():
        with state.lock:
            blocked = {
                ip: {
                    "first_blocked_at": rec.first_blocked_at.isoformat(),
                    "last_seen_at": rec.last_seen_at.isoformat(),
                    "packet_rate_per_min": rec.packet_rate_per_min,
                    "bytes_per_min": rec.bytes_per_min,
                }
                for ip, rec in state.blocked.items()
            }
        return jsonify(blocked)

    return app