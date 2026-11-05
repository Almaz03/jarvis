"""Minimal live Telegram long-polling ingress.

This module only connects Telegram to the durable local inbox. It does not
deliver MCP Events and does not pretend to be the existing dot.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
import re
import time
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .core import Config, Stand, StandError, audit_record


class TelegramTransportError(StandError):
    """Fixed safe error code; never include the token, URL, response, or text."""


TOKEN_PATTERN = re.compile(r"[0-9]{5,20}:[A-Za-z0-9_-]{30,}")
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
STATUS_TEXT = (
    "Telegram ingress работает. Сообщения сохраняются в защищённый inbox. "
    "Связь с существующим dot через MCP Events ещё не подключена."
)


@dataclass(frozen=True)
class TelegramLiveConfig:
    token: str
    owner_user_id: int
    owner_chat_id: int
    state_path: Path
    poll_timeout: int = 50

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> TelegramLiveConfig:
        if env.get("STAND_MODE") != "telegram" or env.get("STAND_ENABLE_LIVE") != "true":
            raise StandError("telegram_live_mode_not_enabled")
        token = env.get("TELEGRAM_BOT_TOKEN", "")
        if not TOKEN_PATTERN.fullmatch(token):
            raise StandError("valid_telegram_bot_token_required")
        try:
            owner_user_id = int(env.get("TELEGRAM_OWNER_USER_ID", ""))
            owner_chat_id = int(env.get("TELEGRAM_OWNER_CHAT_ID", ""))
            poll_timeout = int(env.get("TELEGRAM_POLL_TIMEOUT", "50"))
        except ValueError:
            raise StandError("invalid_telegram_live_configuration") from None
        if not 1 <= poll_timeout <= 50:
            raise StandError("invalid_telegram_live_configuration")
        core = Config(owner_user_id, owner_chat_id,
                      Path(env.get("STAND_STATE_PATH", "/var/lib/jarvis/stand.sqlite3")),
                      mode="telegram", enable_live=True)
        core.validate()
        return cls(token, owner_user_id, owner_chat_id, core.state_path, poll_timeout)

    def stand_config(self) -> Config:
        return Config(self.owner_user_id, self.owner_chat_id, self.state_path,
                      mode="telegram", enable_live=True)


class TelegramClient:
    def __init__(self, token: str, opener: Callable[..., Any] = urlopen):
        if not TOKEN_PATTERN.fullmatch(token):
            raise StandError("valid_telegram_bot_token_required")
        self._base = f"https://api.telegram.org/bot{token}/"
        self._opener = opener

    def _call(self, method: str, values: Mapping[str, Any], timeout: int) -> Any:
        if method not in {"getMe", "getUpdates", "sendMessage"}:
            raise TelegramTransportError("telegram_method_forbidden")
        body = urlencode(values).encode("ascii")
        request = Request(self._base + method, data=body, method="POST",
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with self._opener(request, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError):
            raise TelegramTransportError("telegram_request_failed") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise TelegramTransportError("telegram_response_too_large")
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            raise TelegramTransportError("telegram_invalid_response") from None
        if not isinstance(payload, dict) or payload.get("ok") is not True or "result" not in payload:
            raise TelegramTransportError("telegram_api_rejected_request")
        return payload["result"]

    def get_me(self) -> dict[str, Any]:
        result = self._call("getMe", {}, timeout=15)
        if not isinstance(result, dict) or result.get("is_bot") is not True:
            raise TelegramTransportError("telegram_invalid_bot_identity")
        return result

    def get_updates(self, offset: int, poll_timeout: int) -> list[dict[str, Any]]:
        result = self._call("getUpdates", {
            "offset": offset,
            "timeout": poll_timeout,
            "allowed_updates": json.dumps(["message"], separators=(",", ":")),
        }, timeout=poll_timeout + 15)
        if not isinstance(result, list) or len(result) > 100:
            raise TelegramTransportError("telegram_invalid_updates")
        return result

    def send_message(self, chat_id: int, text: str) -> dict[str, Any]:
        result = self._call("sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": "true",
        }, timeout=15)
        if not isinstance(result, dict):
            raise TelegramTransportError("telegram_invalid_send_result")
        return result


class TelegramWorker:
    def __init__(self, config: TelegramLiveConfig, stand: Stand, client: TelegramClient,
                 emit: Callable[[dict[str, Any]], None] | None = None,
                 sleeper: Callable[[float], None] = time.sleep):
        self.config = config
        self.stand = stand
        self.client = client
        self.emit = emit or (lambda _record: None)
        self.sleeper = sleeper
        with self.stand.db:
            self.stand.db.execute(
                "CREATE TABLE IF NOT EXISTS telegram_runtime "
                "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), next_offset INTEGER NOT NULL)")
            self.stand.db.execute(
                "INSERT OR IGNORE INTO telegram_runtime(singleton,next_offset) VALUES(1,0)")

    def next_offset(self) -> int:
        return int(self.stand.db.execute(
            "SELECT next_offset FROM telegram_runtime WHERE singleton=1").fetchone()[0])

    def _advance(self, update_id: int) -> None:
        with self.stand.db:
            self.stand.db.execute(
                "UPDATE telegram_runtime SET next_offset=max(next_offset,?) WHERE singleton=1",
                (update_id + 1,))

    def process_update(self, update: Any) -> dict[str, Any]:
        if not isinstance(update, dict) or type(update.get("update_id")) is not int:
            raise TelegramTransportError("telegram_invalid_update")
        update_id = update["update_id"]
        result = self.stand.ingest(update)
        if result.get("accepted") is True:
            text = update["message"]["text"].split(maxsplit=1)[0].split("@", 1)[0]
            if text in {"/start", "/status"}:
                # At-most-once acknowledgement: ingress is committed before send. A timeout
                # may lose this status reply, but a replay cannot duplicate it.
                self.client.send_message(self.config.owner_chat_id, STATUS_TEXT)
        self._advance(update_id)
        record = audit_record(result)
        self.emit(record)
        return record

    def run_forever(self) -> None:
        identity = self.client.get_me()
        self.emit({"status": "telegram_worker_started", "bot_id_present": "id" in identity,
                   "dot_connected": False})
        delay = 1
        while True:
            try:
                updates = self.client.get_updates(self.next_offset(), self.config.poll_timeout)
                for update in updates:
                    self.process_update(update)
                delay = 1
            except TelegramTransportError as error:
                self.emit({"status": "telegram_transport_retry", "error": str(error)})
                self.sleeper(delay)
                delay = min(delay * 2, 30)
