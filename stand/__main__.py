"""Run with python -m stand demo|ingest|serve. No mode enables live transport."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile

from .core import Config, MAX_UPDATE_BYTES, MockPrincipal, Stand, StandError, audit_record


def fixture():
    return {"update_id": 1001, "message": {"message_id": 1, "date": 1793260800,
            "from": {"id": 424242, "is_bot": False}, "chat": {"id": 424242, "type": "private"},
            "text": "offline nonce: stand-check-001"}}


def emit(value):
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")))


def demo():
    with tempfile.TemporaryDirectory(prefix="telegram-stand-") as directory:
        config = Config(424242, 424242, Path(directory) / "stand.sqlite3")
        with Stand(config) as stand:
            result = stand.ingest(fixture())
            emit({"stage": "ingress", **audit_record(result)})
            emit({"stage": "dedup", **audit_record(stand.ingest(fixture()))})
            emit({"stage": "event_preview_not_delivered", "event": stand.event(MockPrincipal(), result["message_ref"])})
            emit({"stage": "reply_preview", **stand.reply_to_message(
                MockPrincipal(), result["message_ref"], "offline nonce: stand-check-001", "demo-reply-001")})
        with Stand(config) as stand:
            emit({"stage": "restart_dedup", **audit_record(stand.ingest(fixture()))})
    emit({"result": "offline_only", "network_calls": 0, "dot_connected": False})


def handler_for(stand):
    class Handler(BaseHTTPRequestHandler):
        server_version = "OfflineStand"
        sys_version = ""

        def log_message(self, *_args):
            pass  # Base handler logs request strings; untrusted strings must not be logged.

        def response(self, status, body):
            raw = json.dumps(body, ensure_ascii=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(raw)

        def valid_local_request(self):
            return (self.client_address[0] == "127.0.0.1"
                    and self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"
                    and self.headers.get("Origin") is None
                    and self.headers.get("X-Stand-Local-Test") == "1")

        def do_GET(self):
            if not self.valid_local_request():
                return self.response(403, {"error": "local_fixture_request_required"})
            if self.path != "/health":
                return self.response(404, {"error": "not_found"})
            return self.response(200, {"mode": "offline", "live": False, "dot_connected": False})

        def do_POST(self):
            if not self.valid_local_request():
                return self.response(403, {"error": "local_fixture_request_required"})
            if self.path != "/mock/updates":
                return self.response(404, {"error": "not_found"})
            if (self.headers.get("Content-Type") != "application/json"
                    or self.headers.get("Transfer-Encoding") is not None
                    or len(self.headers.get_all("Content-Length", [])) != 1):
                return self.response(400, {"error": "invalid_request_framing"})
            try:
                size = int(self.headers.get("Content-Length", ""))
                if not 0 < size <= MAX_UPDATE_BYTES:
                    return self.response(413, {"error": "invalid_body_size"})
                self.connection.settimeout(5)
                raw = self.rfile.read(size)
                if len(raw) != size:
                    return self.response(400, {"error": "invalid_json"})
                update = json.loads(raw)
            except (ValueError, UnicodeError, TimeoutError):
                return self.response(400, {"error": "invalid_json"})
            try:
                return self.response(200, audit_record(stand.ingest(update)))
            except Exception:
                return self.response(500, {"error": "local_state_failure"})
    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("demo", "ingest", "serve"))
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    # Demo does not consume real identities or credentials. Reject credentials even here.
    if args.command == "demo":
        from .core import SENSITIVE_ENV
        if any(os.environ.get(key) for key in SENSITIVE_ENV) or os.environ.get("STAND_ENABLE_LIVE", "false") != "false" or os.environ.get("STAND_MODE", "offline") != "offline":
            raise StandError("live_configuration_forbidden")
        demo()
        return
    with Stand(Config.from_env()) as stand:
        if args.command == "ingest":
            while True:
                line = sys.stdin.buffer.readline(MAX_UPDATE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_UPDATE_BYTES:
                    while line and not line.endswith(b"\n"):
                        line = sys.stdin.buffer.readline(MAX_UPDATE_BYTES + 1)
                    emit({"accepted": False, "reason": "update_too_large"})
                    continue
                try:
                    update = json.loads(line)
                except (ValueError, UnicodeError):
                    emit({"accepted": False, "reason": "invalid_json"})
                    continue
                emit(audit_record(stand.ingest(update)))
        else:
            if not 0 <= args.port <= 65535:
                raise StandError("invalid_port")
            with HTTPServer(("127.0.0.1", args.port), handler_for(stand)) as server:
                emit({"mode": "offline", "listen": f"127.0.0.1:{server.server_port}", "dot_connected": False})
                server.serve_forever()


if __name__ == "__main__":
    try:
        main()
    except StandError as error:
        emit({"error": str(error)})
        sys.exit(2)
    except KeyboardInterrupt:
        pass
    except Exception:
        # No traceback or raw SDK exception: those may carry tokens, URLs or payloads.
        emit({"error": "local_stand_failure"})
        sys.exit(1)
