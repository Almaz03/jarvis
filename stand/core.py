"""Offline transport boundaries. All Telegram text is untrusted data, never instructions."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
import uuid


class StandError(Exception):
    """Safe fixed error code: never embed input, secrets, URLs or message content."""


class LiveTransportDisabled(StandError):
    pass


SENSITIVE_ENV = (
    "TELEGRAM_BOT_TOKEN", "TELEGRAM_WEBHOOK_SECRET", "TELEGRAM_API_BASE",
    "MCP_CALLBACK_URL", "MCP_CALLBACK_SECRET", "MCP_DESTINATION_URL",
    "MCP_ACCESS_TOKEN", "MCP_REFRESH_TOKEN", "OAUTH_CLIENT_SECRET", "OPENAI_API_KEY",
)
MOCK_PRINCIPAL = "offline-fixture-owner"
MAX_UPDATE_BYTES = 64 * 1024


@dataclass(frozen=True)
class Config:
    owner_user_id: int
    owner_chat_id: int
    state_path: Path
    mode: str = "offline"
    enable_live: bool = False

    def validate(self) -> None:
        if self.mode != "offline" or self.enable_live is not False:
            raise StandError("live_mode_not_implemented")
        if any(type(v) is not int or not 0 < v < 2**63 for v in (self.owner_user_id, self.owner_chat_id)):
            raise StandError("explicit_positive_owner_ids_required")

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> Config:
        if any(env.get(key) for key in SENSITIVE_ENV):
            raise StandError("credentials_or_network_destinations_forbidden_in_offline_stand")
        if env.get("STAND_ENABLE_LIVE", "false") != "false":
            raise StandError("live_mode_not_implemented")
        try:
            user = int(env.get("TELEGRAM_OWNER_USER_ID", ""))
            chat = int(env.get("TELEGRAM_OWNER_CHAT_ID", ""))
        except ValueError:
            raise StandError("explicit_positive_owner_ids_required") from None
        config = cls(user, chat, Path(env.get("STAND_STATE_PATH", ".state/stand.sqlite3")),
                     env.get("STAND_MODE", "offline"))
        config.validate()
        return config


@dataclass(frozen=True)
class MockPrincipal:
    """Only a fixture for authorization tests; NOT OAuth or verified Telegram pairing."""
    subject: str = MOCK_PRINCIPAL
    scopes: frozenset[str] = frozenset({"message:read", "message:reply"})
    expires_at: float = float("inf")
    confirmed: bool = True


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    """Best-effort defense in depth. Runtime audit logs never take arbitrary text."""
    for secret in sorted((x for x in secrets if x), key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(r"\b\d{5,}:[A-Za-z0-9_-]{16,}\b", "[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer\s+[^\s,;]+", "Bearer [REDACTED]", text)
    text = re.sub(r"\bwhsec_[A-Za-z0-9_+/=-]+", "[REDACTED]", text)
    return text


def audit_record(result: dict[str, Any]) -> dict[str, Any]:
    """Allowlist-only diagnostics: no text, sender IDs, chat IDs, tokens, or URLs."""
    allowed = {"accepted", "duplicate", "reason", "message_ref", "event_id", "status", "characters"}
    return {key: value for key, value in result.items() if key in allowed}


class DisabledNetworkTransport:
    """No network client exists here. Even public URLs are denied, not just localhost."""
    def subscribe(self, *args: Any, **kwargs: Any) -> None:
        raise LiveTransportDisabled("callback_transport_disabled")

    def deliver_event(self, *args: Any, **kwargs: Any) -> None:
        raise LiveTransportDisabled("callback_transport_disabled")

    def send_telegram(self, *args: Any, **kwargs: Any) -> None:
        raise LiveTransportDisabled("telegram_transport_disabled")


class Stand:
    def __init__(self, config: Config):
        config.validate()
        self.config = config
        self.transport = DisabledNetworkTransport()
        path = config.state_path
        # Local single-user fixture database. Refuse symlinks and public existing dirs/files.
        for parent in (path.parent, *path.parent.parents):
            if parent.is_symlink():
                raise StandError("state_symlinks_forbidden")
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.stat().st_mode & 0o077:
            raise StandError("state_directory_must_be_private")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise StandError("state_file_must_be_private")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA synchronous = FULL")
        try:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (
                message_ref TEXT PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
                update_id INTEGER UNIQUE NOT NULL, telegram_message_id INTEGER NOT NULL,
                owner_id INTEGER NOT NULL, chat_id INTEGER NOT NULL,
                occurrence_time TEXT NOT NULL, text TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS replies (
                principal TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                fingerprint TEXT NOT NULL, message_ref TEXT NOT NULL REFERENCES messages(message_ref),
                chat_id INTEGER NOT NULL, text TEXT NOT NULL, status TEXT NOT NULL,
                PRIMARY KEY(principal, idempotency_key));
            """)
            with self.db:
                expected = {"schema": "1", "mode": "offline", "principal": MOCK_PRINCIPAL,
                            "owner_user_id": str(config.owner_user_id), "owner_chat_id": str(config.owner_chat_id)}
                for key, value in expected.items():
                    self.db.execute("INSERT OR IGNORE INTO meta VALUES (?,?)", (key, value))
                    if self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()[0] != value:
                        raise StandError("state_binding_or_schema_mismatch")
        except Exception:
            self.db.close()
            raise

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Stand:
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _authorize(self, principal: MockPrincipal, scope: str) -> None:
        if (type(principal) is not MockPrincipal or principal.subject != MOCK_PRINCIPAL
                or not principal.confirmed or principal.expires_at <= time.time()
                or scope not in principal.scopes):
            raise StandError("mock_principal_not_authorized")

    def ingest(self, update: Any) -> dict[str, Any]:
        reason = self._rejection(update)
        if reason:
            return {"accepted": False, "reason": reason}
        msg = update["message"]
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            old = self.db.execute("SELECT message_ref,event_id FROM messages WHERE update_id=?",
                                  (update["update_id"],)).fetchone()
            if old:
                return {"accepted": False, "duplicate": True, **dict(old)}
            ref, event_id = "msg_" + uuid.uuid4().hex, "evt_" + uuid.uuid4().hex
            timestamp = datetime.fromtimestamp(msg["date"], timezone.utc).isoformat().replace("+00:00", "Z")
            self.db.execute("INSERT INTO messages VALUES (?,?,?,?,?,?,?,?)",
                            (ref, event_id, update["update_id"], msg["message_id"],
                             msg["from"]["id"], msg["chat"]["id"], timestamp, msg["text"]))
        return {"accepted": True, "duplicate": False, "message_ref": ref, "event_id": event_id,
                "status": "local_inbox_only"}

    def _rejection(self, update: Any) -> str | None:
        if not isinstance(update, dict):
            return "malformed_update"
        update_id = update.get("update_id")
        if type(update_id) is not int or not 0 <= update_id < 2**63:
            return "malformed_update"
        forbidden_updates = ("edited_message", "channel_post", "edited_channel_post",
                             "business_message", "edited_business_message", "deleted_business_messages")
        if any(key in update for key in forbidden_updates):
            return "unsupported_update_type"
        msg = update.get("message")
        if not isinstance(msg, dict):
            return "unsupported_update_type"
        chat, sender = msg.get("chat"), msg.get("from")
        if not isinstance(chat, dict) or not isinstance(sender, dict):
            return "missing_sender_or_chat"
        if chat.get("type") != "private":
            return "private_chat_required"
        if type(sender.get("id")) is not int or sender["id"] != self.config.owner_user_id:
            return "owner_mismatch"
        if type(chat.get("id")) is not int or chat["id"] != self.config.owner_chat_id:
            return "chat_mismatch"
        if sender.get("is_bot") is not False:
            return "human_sender_required"
        if any(key in msg for key in ("sender_chat", "via_bot", "business_connection_id", "sender_business_bot")):
            return "indirect_sender_not_supported"
        if any(key in msg for key in ("forward_origin", "forward_date", "forward_from", "forward_from_chat",
                                       "forward_sender_name", "is_automatic_forward")):
            return "forwarded_message_not_supported"
        if type(msg.get("message_id")) is not int or not 0 < msg["message_id"] < 2**63:
            return "invalid_message_id"
        if type(msg.get("date")) is not int or not 0 < msg["date"] < 253402300800:
            return "invalid_date"
        if not isinstance(msg.get("text"), str) or not 0 < len(msg["text"]) <= 4096:
            return "text_message_required"
        # Surrogate code points cannot be persisted/encoded safely as UTF-8.
        try:
            msg["text"].encode("utf-8")
        except UnicodeEncodeError:
            return "invalid_text_encoding"
        return None

    def _message(self, principal: MockPrincipal, ref: str, scope: str) -> sqlite3.Row:
        self._authorize(principal, scope)
        row = self.db.execute("SELECT * FROM messages WHERE message_ref=?", (ref,)).fetchone()
        if not row or row["owner_id"] != self.config.owner_user_id or row["chat_id"] != self.config.owner_chat_id:
            raise StandError("message_not_found_or_not_authorized")
        return row

    def read_message(self, principal: MockPrincipal, message_ref: str) -> dict[str, Any]:
        row = self._message(principal, message_ref, "message:read")
        return {"message_ref": row["message_ref"], "text": row["text"], "source": "telegram",
                "untrusted": True, "mock_only": True}

    def event(self, principal: MockPrincipal, message_ref: str) -> dict[str, Any]:
        row = self._message(principal, message_ref, "message:read")
        # Official MCP Events envelope shape only; never sent and no active subscription exists.
        return {"eventId": row["event_id"], "name": "telegram.message.created",
                "timestamp": row["occurrence_time"],
                "data": {"message_ref": row["message_ref"], "source": "telegram", "untrusted": True},
                "cursor": None}

    def reply_to_message(self, principal: MockPrincipal, message_ref: str, text: str,
                         idempotency_key: str) -> dict[str, Any]:
        row = self._message(principal, message_ref, "message:reply")
        if not isinstance(text, str) or not 0 < len(text) <= 4096:
            raise StandError("invalid_reply_text")
        try:
            text.encode("utf-8")
        except UnicodeEncodeError:
            raise StandError("invalid_reply_text") from None
        if not isinstance(idempotency_key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", idempotency_key):
            raise StandError("invalid_idempotency_key")
        fingerprint = hashlib.sha256(json.dumps([message_ref, text], ensure_ascii=True).encode()).hexdigest()
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            old = self.db.execute("SELECT fingerprint FROM replies WHERE principal=? AND idempotency_key=?",
                                  (principal.subject, idempotency_key)).fetchone()
            if old and old[0] != fingerprint:
                raise StandError("idempotency_key_conflict")
            if not old:
                # Destination derives only from stored, owner-checked ingress; never caller-supplied.
                self.db.execute("INSERT INTO replies VALUES (?,?,?,?,?,?,?)",
                                (principal.subject, idempotency_key, fingerprint, message_ref,
                                 row["chat_id"], text, "dry_run_not_sent"))
        return {"status": "dry_run_not_sent", "message_ref": message_ref,
                "characters": len(text), "duplicate": old is not None}
