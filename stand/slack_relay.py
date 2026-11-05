"""Owner-scoped Slack transport and a fail-closed one-time relay test.

The production relay remains disabled.  The command in this module can only
send one fixed test message after an explicit ephemeral approval value.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .core import StandError
from .slack_oauth import USER_TOKEN, SlackOAuthConfig, SlackOAuthStore


SLACK_API = "https://slack.com/api/"
SLACK_TARGET_DM_ID = "D0C7SAYJB24"
SLACK_DOT_BOT_ID = "B0C6GJAMC23"
SLACK_RELAY_TEST_KEY = "owner-dm-relay-test-v1"
SLACK_RELAY_TEST_TEXT = "relay-test: ответь OK"
SLACK_RELAY_TEST_APPROVAL = "relay-test-v1-approved"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
SLACK_TS = re.compile(r"^[0-9]{10,16}\.[0-9]{6}$")


class SlackTransportError(StandError):
    """A fixed error code; never contains a token, URL or Slack payload."""


@dataclass(frozen=True)
class SlackRelayTestConfig:
    oauth: SlackOAuthConfig
    approval: str

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "SlackRelayTestConfig":
        oauth = SlackOAuthConfig.from_env(env)
        if oauth is None:
            raise StandError("slack_oauth_not_enabled")
        if oauth.target_dm_id != SLACK_TARGET_DM_ID:
            raise StandError("fixed_slack_target_dm_required")
        approval = env.get("SLACK_RELAY_TEST_APPROVAL", "")
        if approval != SLACK_RELAY_TEST_APPROVAL:
            raise StandError("explicit_slack_relay_test_approval_required")
        return cls(oauth, approval)


class SlackWebClient:
    def __init__(self, token: str, opener: Callable[..., Any] = urlopen):
        # SlackOAuthStore already validates the user-token shape.  Keep this
        # client ignorant of environment variables and persistent storage.
        if not isinstance(token, str) or not USER_TOKEN.fullmatch(token):
            raise SlackTransportError("slack_user_token_required")
        self._token = token
        self._opener = opener

    def _call(self, method: str, values: Mapping[str, Any]) -> dict[str, Any]:
        if method not in {"conversations.history", "chat.postMessage"}:
            raise SlackTransportError("slack_method_forbidden")
        body = urlencode(values).encode("utf-8")
        request = Request(SLACK_API + method, data=body, method="POST", headers={
            "Authorization": "Bearer " + self._token,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        })
        try:
            with self._opener(request, timeout=15) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError):
            raise SlackTransportError("slack_request_failed") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SlackTransportError("slack_response_too_large")
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeError):
            raise SlackTransportError("slack_invalid_response") from None
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise SlackTransportError("slack_api_rejected_request")
        return payload

    def history(self, oldest: str, cursor: str = "") -> tuple[list[dict[str, Any]], str]:
        if not SLACK_TS.fullmatch(oldest):
            raise SlackTransportError("invalid_slack_history_boundary")
        values: dict[str, Any] = {
            "channel": SLACK_TARGET_DM_ID,
            "oldest": oldest,
            "inclusive": "true",
            "limit": "100",
        }
        if cursor:
            values["cursor"] = cursor
        payload = self._call("conversations.history", values)
        messages = payload.get("messages")
        metadata = payload.get("response_metadata", {})
        next_cursor = metadata.get("next_cursor", "") if isinstance(metadata, dict) else ""
        if (not isinstance(messages, list) or len(messages) > 100
                or not isinstance(next_cursor, str) or len(next_cursor) > 2048):
            raise SlackTransportError("slack_invalid_history_response")
        return [message for message in messages if isinstance(message, dict)], next_cursor

    def post_test_message(self) -> str:
        payload = self._call("chat.postMessage", {
            "channel": SLACK_TARGET_DM_ID,
            "text": SLACK_RELAY_TEST_TEXT,
            "mrkdwn": "false",
            "unfurl_links": "false",
            "unfurl_media": "false",
        })
        if payload.get("channel") != SLACK_TARGET_DM_ID:
            raise SlackTransportError("slack_unexpected_post_destination")
        timestamp = payload.get("ts")
        if not isinstance(timestamp, str) or not SLACK_TS.fullmatch(timestamp):
            raise SlackTransportError("slack_invalid_post_response")
        return timestamp


class OneTimeSlackRelayTest:
    """Durable one-send test; uncertain sends are never retried automatically."""

    def __init__(self, db: sqlite3.Connection, lock: threading.RLock,
                 oauth: SlackOAuthConfig, client: SlackWebClient,
                 clock: Callable[[], float] = time.time,
                 sleeper: Callable[[float], None] = time.sleep):
        self.db = db
        self.lock = lock
        self.oauth = oauth
        self.client = client
        self.clock = clock
        self.sleeper = sleeper
        with self.lock, self.db:
            self.db.execute("""CREATE TABLE IF NOT EXISTS slack_relay_one_time_tests (
              test_key TEXT PRIMARY KEY,
              status TEXT NOT NULL,
              slack_ts TEXT,
              reply_ts TEXT,
              created_at INTEGER NOT NULL,
              updated_at INTEGER NOT NULL)
            """)

    @staticmethod
    def _boundary(timestamp: float) -> str:
        return f"{max(1, int(timestamp)):010d}.000000"

    def _row(self) -> sqlite3.Row:
        with self.lock, self.db:
            now = int(self.clock())
            self.db.execute(
                "INSERT OR IGNORE INTO slack_relay_one_time_tests "
                "(test_key,status,slack_ts,reply_ts,created_at,updated_at) "
                "VALUES(?, 'pending', NULL, NULL, ?, ?)",
                (SLACK_RELAY_TEST_KEY, now, now))
            return self.db.execute(
                "SELECT * FROM slack_relay_one_time_tests WHERE test_key=?",
                (SLACK_RELAY_TEST_KEY,)).fetchone()

    def _update(self, status: str, slack_ts: str | None = None,
                reply_ts: str | None = None) -> None:
        with self.lock, self.db:
            self.db.execute(
                "UPDATE slack_relay_one_time_tests SET status=?, "
                "slack_ts=COALESCE(?,slack_ts),reply_ts=COALESCE(?,reply_ts),updated_at=? "
                "WHERE test_key=?",
                (status, slack_ts, reply_ts, int(self.clock()), SLACK_RELAY_TEST_KEY))

    def _history(self, oldest: str) -> list[dict[str, Any]]:
        messages: list[dict[str, Any]] = []
        cursor = ""
        for _page in range(5):
            page, cursor = self.client.history(oldest, cursor)
            messages.extend(page)
            if not cursor:
                break
        else:
            raise SlackTransportError("slack_history_scan_limit_exceeded")
        return messages

    def _existing_test(self, oldest: str) -> str | None:
        matches = []
        for message in self._history(oldest):
            if (message.get("type") == "message"
                    and message.get("subtype") is None
                    and message.get("user") == self.oauth.owner_user_id
                    and message.get("text") == SLACK_RELAY_TEST_TEXT
                    and isinstance(message.get("ts"), str)
                    and SLACK_TS.fullmatch(message["ts"])):
                matches.append(message["ts"])
        return max(matches) if matches else None

    def _matching_reply(self, slack_ts: str) -> str | None:
        matches = []
        for message in self._history(slack_ts):
            timestamp = message.get("ts")
            if (message.get("type") == "message"
                    and timestamp != slack_ts
                    and isinstance(timestamp, str)
                    and SLACK_TS.fullmatch(timestamp)
                    and message.get("bot_id") == SLACK_DOT_BOT_ID
                    and message.get("text", "").strip() == "OK"):
                matches.append(timestamp)
        return min(matches) if matches else None

    def run(self, wait_seconds: int = 90) -> dict[str, Any]:
        if type(wait_seconds) is not int or not 0 <= wait_seconds <= 120:
            raise StandError("invalid_slack_relay_test_wait")
        row = self._row()
        oldest = self._boundary(max(int(row["created_at"]) - 300,
                                    int(self.clock()) - 86400))
        existing = self._existing_test(oldest)
        duplicate_prevented = False
        if existing:
            duplicate_prevented = row["slack_ts"] != existing or row["status"] in {
                "pending", "sending", "send_uncertain"}
            self._update("sent", slack_ts=existing)
            slack_ts = existing
        elif row["status"] in {"sending", "send_uncertain", "sent", "replied"}:
            # A prior process may have sent the request and crashed before
            # recording Slack's response. Never turn uncertainty into a retry.
            return {"status": "send_uncertain", "duplicate_prevented": True}
        else:
            self._update("sending")
            try:
                slack_ts = self.client.post_test_message()
            except SlackTransportError:
                self._update("send_uncertain")
                return {"status": "send_uncertain", "duplicate_prevented": True}
            self._update("sent", slack_ts=slack_ts)

        deadline = self.clock() + wait_seconds
        while True:
            reply_ts = self._matching_reply(slack_ts)
            if reply_ts:
                self._update("replied", reply_ts=reply_ts)
                return {"status": "reply_verified", "slack_ts": slack_ts,
                        "reply_ts": reply_ts, "duplicate_prevented": duplicate_prevented}
            if self.clock() >= deadline:
                return {"status": "sent_no_reply_yet", "slack_ts": slack_ts,
                        "duplicate_prevented": duplicate_prevented}
            self.sleeper(min(3, max(0, deadline - self.clock())))


def build_one_time_test(db: sqlite3.Connection, lock: threading.RLock,
                        config: SlackRelayTestConfig,
                        client_factory: Callable[[str], SlackWebClient] = SlackWebClient,
                        clock: Callable[[], float] = time.time,
                        sleeper: Callable[[float], None] = time.sleep) -> OneTimeSlackRelayTest:
    store = SlackOAuthStore(db, lock, config.oauth)
    token = store.load_installation_token()
    return OneTimeSlackRelayTest(db, lock, config.oauth, client_factory(token), clock, sleeper)
