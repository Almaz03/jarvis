"""Disabled-by-default Slack OAuth callback preparation.

This module only installs and stores an owner-scoped Slack user grant. It does
not send, read, or relay Slack messages.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlencode

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from .core import StandError


SLACK_SCOPES = frozenset({"chat:write", "im:history"})
SLACK_REDIRECT_URI = "https://jarvis.akalmaz.tech/slack/oauth/callback"
STATE_TTL = 600
MAX_RESPONSE = 64 * 1024
SLACK_ID = re.compile(r"^[A-Z][A-Z0-9]{8,20}$")
CLIENT_ID = re.compile(r"^[0-9]{5,20}\.[0-9]{5,20}$")
OAUTH_CODE = re.compile(r"^[A-Za-z0-9._-]{10,2048}$")
USER_TOKEN = re.compile(r"^(?:xoxp-|xoxe\.xoxp-)[A-Za-z0-9._-]{20,2048}$")


class SlackOAuthError(Exception):
    def __init__(self, code: str, status: int = 400,
                 diagnostic: dict[str, str] | None = None):
        self.code = code
        self.status = status
        self.diagnostic = diagnostic


def _value_kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, str):
        return "string"
    return "other"


def _field_kind(value: Mapping[str, Any], field: str) -> str:
    return "missing" if field not in value else _value_kind(value[field])


def _member_kind(value: Any, field: str) -> str:
    return _field_kind(value, field) if isinstance(value, dict) else "unavailable"


def oauth_shape_diagnostic(result: Mapping[str, Any]) -> dict[str, str]:
    """Return an allowlisted type-only summary; never copy response values."""
    team = result.get("team")
    user = result.get("authed_user")
    return {
        "team": _field_kind(result, "team"),
        "authed_user": _field_kind(result, "authed_user"),
        "team_id": _member_kind(team, "id"),
        "authed_user_id": _member_kind(user, "id"),
        "authed_user_scope": _member_kind(user, "scope"),
        "authed_user_access_token": _member_kind(user, "access_token"),
        "authed_user_token_type": _member_kind(user, "token_type"),
        "top_level_scope": _field_kind(result, "scope"),
        "top_level_access_token": _field_kind(result, "access_token"),
        "top_level_token_type": _field_kind(result, "token_type"),
        "top_level_team_id": _field_kind(result, "team_id"),
        "top_level_user_id": _field_kind(result, "user_id"),
    }


def _strict_bool(value: str, name: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise StandError(f"{name}_must_be_true_or_false")


def _decode_key(value: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(value.encode("ascii"))
    except (ValueError, UnicodeError):
        raise StandError("valid_slack_token_encryption_key_required") from None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode("ascii") != value:
        raise StandError("valid_slack_token_encryption_key_required")
    return raw


@dataclass(frozen=True)
class SlackOAuthConfig:
    app_id: str
    team_id: str
    owner_user_id: str
    target_dm_id: str
    client_id: str
    client_secret: str
    setup_token: str
    encryption_key: bytes

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "SlackOAuthConfig | None":
        enabled = _strict_bool(env.get("SLACK_OAUTH_ENABLED", "false"), "slack_oauth_enabled")
        relay_enabled = _strict_bool(env.get("SLACK_RELAY_ENABLED", "false"), "slack_relay_enabled")
        if relay_enabled:
            raise StandError("slack_relay_not_implemented")
        if not enabled:
            return None
        values = {name: env.get(name, "").strip() for name in (
            "SLACK_APP_ID", "SLACK_TEAM_ID", "SLACK_OWNER_USER_ID", "SLACK_TARGET_DM_ID",
            "SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET", "SLACK_OAUTH_SETUP_TOKEN",
            "SLACK_TOKEN_ENCRYPTION_KEY",
        )}
        if values["SLACK_APP_ID"] != "A0CFN4GD8L8":
            raise StandError("fixed_slack_app_id_required")
        if values["SLACK_TEAM_ID"] != "T039VA2H3V5":
            raise StandError("fixed_slack_team_id_required")
        if values["SLACK_TARGET_DM_ID"] != "D0C7SAYJB24":
            raise StandError("fixed_slack_target_dm_required")
        if not SLACK_ID.fullmatch(values["SLACK_OWNER_USER_ID"]):
            raise StandError("explicit_slack_owner_user_id_required")
        if not CLIENT_ID.fullmatch(values["SLACK_CLIENT_ID"]):
            raise StandError("valid_slack_client_id_required")
        if not 24 <= len(values["SLACK_CLIENT_SECRET"]) <= 256:
            raise StandError("valid_slack_client_secret_required")
        if not 32 <= len(values["SLACK_OAUTH_SETUP_TOKEN"]) <= 256:
            raise StandError("valid_slack_oauth_setup_token_required")
        key = _decode_key(values["SLACK_TOKEN_ENCRYPTION_KEY"])
        return cls(values["SLACK_APP_ID"], values["SLACK_TEAM_ID"],
                   values["SLACK_OWNER_USER_ID"], values["SLACK_TARGET_DM_ID"],
                   values["SLACK_CLIENT_ID"], values["SLACK_CLIENT_SECRET"],
                   values["SLACK_OAUTH_SETUP_TOKEN"], key)


class SlackOAuthStore:
    def __init__(self, db: sqlite3.Connection, lock: threading.RLock,
                 config: SlackOAuthConfig):
        self.db = db
        self.lock = lock
        self.config = config
        with self.lock, self.db:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS slack_oauth_states (
              state_hash TEXT PRIMARY KEY,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              used_at INTEGER);
            CREATE TABLE IF NOT EXISTS slack_installation (
              singleton INTEGER PRIMARY KEY CHECK(singleton=1),
              app_id TEXT NOT NULL,
              team_id TEXT NOT NULL,
              owner_user_id TEXT NOT NULL,
              scopes TEXT NOT NULL,
              token_ciphertext TEXT NOT NULL,
              installed_at INTEGER NOT NULL);
            """)

    @staticmethod
    def _state_hash(state: str) -> str:
        return hashlib.sha256(state.encode("ascii")).hexdigest()

    def create_state(self, now: int) -> str:
        state = secrets.token_urlsafe(32)
        digest = self._state_hash(state)
        with self.lock, self.db:
            self.db.execute("DELETE FROM slack_oauth_states WHERE expires_at<? OR used_at IS NOT NULL",
                            (now,))
            self.db.execute("INSERT INTO slack_oauth_states VALUES (?,?,?,NULL)",
                            (digest, now, now + STATE_TTL))
        return state

    def consume_state(self, state: str, now: int) -> None:
        if not isinstance(state, str) or not 32 <= len(state) <= 128 or not state.isascii():
            raise SlackOAuthError("invalid_oauth_state")
        digest = self._state_hash(state)
        with self.lock, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute(
                "SELECT expires_at,used_at FROM slack_oauth_states WHERE state_hash=?", (digest,)).fetchone()
            if not row or row["used_at"] is not None or int(row["expires_at"]) < now:
                raise SlackOAuthError("invalid_oauth_state")
            self.db.execute("UPDATE slack_oauth_states SET used_at=? WHERE state_hash=?", (now, digest))

    def save_installation(self, token: str, now: int) -> None:
        nonce = os.urandom(12)
        aad = f"slack-installation-v1|{self.config.team_id}|{self.config.owner_user_id}".encode()
        encrypted = AESGCM(self.config.encryption_key).encrypt(nonce, token.encode("utf-8"), aad)
        ciphertext = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")
        scopes = ",".join(sorted(SLACK_SCOPES))
        with self.lock, self.db:
            self.db.execute("""INSERT INTO slack_installation
              (singleton,app_id,team_id,owner_user_id,scopes,token_ciphertext,installed_at)
              VALUES(1,?,?,?,?,?,?)
              ON CONFLICT(singleton) DO UPDATE SET
                app_id=excluded.app_id,team_id=excluded.team_id,
                owner_user_id=excluded.owner_user_id,scopes=excluded.scopes,
                token_ciphertext=excluded.token_ciphertext,installed_at=excluded.installed_at""",
              (self.config.app_id, self.config.team_id, self.config.owner_user_id,
               scopes, ciphertext, now))


def exchange_code(config: SlackOAuthConfig, code: str) -> dict[str, Any]:
    body = urlencode({"code": code, "redirect_uri": SLACK_REDIRECT_URI,
                      "grant_type": "authorization_code"}).encode("ascii")
    credentials = base64.b64encode(
        f"{config.client_id}:{config.client_secret}".encode("utf-8")).decode("ascii")
    connection = http.client.HTTPSConnection("slack.com", 443, timeout=10,
                                              context=ssl.create_default_context())
    try:
        connection.request("POST", "/api/oauth.v2.user.access", body=body, headers={
            "Authorization": "Basic " + credentials,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        })
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE + 1)
        if response.status != 200 or len(raw) > MAX_RESPONSE:
            raise SlackOAuthError("slack_oauth_exchange_failed", 502)
        value = json.loads(raw)
    except SlackOAuthError:
        raise
    except Exception:
        raise SlackOAuthError("slack_oauth_exchange_failed", 502) from None
    finally:
        connection.close()
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise SlackOAuthError("slack_oauth_exchange_failed", 502)
    return value


def verify_token_identity(token: str) -> dict[str, Any]:
    """Ask Slack which workspace and user the newly issued token belongs to."""
    connection = http.client.HTTPSConnection("slack.com", 443, timeout=10,
                                              context=ssl.create_default_context())
    try:
        connection.request("POST", "/api/auth.test", body=b"", headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        })
        response = connection.getresponse()
        raw = response.read(MAX_RESPONSE + 1)
        if response.status != 200 or len(raw) > MAX_RESPONSE:
            raise SlackOAuthError("slack_oauth_identity_verification_failed", 502)
        value = json.loads(raw)
    except SlackOAuthError:
        raise
    except Exception:
        raise SlackOAuthError("slack_oauth_identity_verification_failed", 502) from None
    finally:
        connection.close()
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise SlackOAuthError("slack_oauth_identity_verification_failed", 502)
    return value


class SlackOAuthService:
    def __init__(self, config: SlackOAuthConfig, db: sqlite3.Connection,
                 lock: threading.RLock,
                 exchanger: Callable[[SlackOAuthConfig, str], dict[str, Any]] = exchange_code,
                 identity_verifier: Callable[[str], dict[str, Any]] = verify_token_identity,
                 clock: Callable[[], float] = time.time):
        self.config = config
        self.store = SlackOAuthStore(db, lock, config)
        self.exchanger = exchanger
        self.identity_verifier = identity_verifier
        self.clock = clock

    def _authorized_setup(self, request: Request) -> bool:
        header = request.headers.get("authorization", "")
        expected = "Bearer " + self.config.setup_token
        return len(header) <= 512 and hmac.compare_digest(header, expected)

    async def start(self, request: Request) -> Response:
        if not self._authorized_setup(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401,
                                headers={"Cache-Control": "no-store"})
        state = self.store.create_state(int(self.clock()))
        url = "https://slack.com/oauth/v2_user/authorize?" + urlencode({
            "client_id": self.config.client_id,
            "scope": ",".join(sorted(SLACK_SCOPES)),
            "redirect_uri": SLACK_REDIRECT_URI,
            "state": state,
            "team": self.config.team_id,
        })
        return JSONResponse({"authorization_url": url}, headers={
            "Cache-Control": "no-store", "Pragma": "no-cache",
        })

    async def callback(self, request: Request) -> Response:
        try:
            state = request.query_params.get("state", "")
            self.store.consume_state(state, int(self.clock()))
            if request.query_params.get("error"):
                raise SlackOAuthError("slack_oauth_denied")
            code = request.query_params.get("code", "")
            if not OAUTH_CODE.fullmatch(code):
                raise SlackOAuthError("invalid_oauth_code")
            result = self.exchanger(self.config, code)
            team = result.get("team")
            user = result.get("authed_user")
            diagnostic = oauth_shape_diagnostic(result)
            identity_shape_complete = (isinstance(team, dict)
                                       and isinstance(team.get("id"), str)
                                       and isinstance(user, dict)
                                       and isinstance(user.get("id"), str))
            # oauth.v2.user.access documents token fields at the top level,
            # while oauth.v2.access places the user grant inside authed_user
            # (and may use the top level for a bot grant). Prefer the explicit
            # nested user grant when present, otherwise accept the user-centric
            # response shape. Identity/scope checks below remain identical.
            nested_grant = (isinstance(user, dict)
                            and ("token_type" in user or "access_token" in user))
            token_type = user.get("token_type") if nested_grant else result.get("token_type")
            token = user.get("access_token") if nested_grant else result.get("access_token")
            if token_type != "user":
                raise SlackOAuthError("slack_oauth_token_type_mismatch", 403)
            if not isinstance(token, str) or not USER_TOKEN.fullmatch(token):
                raise SlackOAuthError("invalid_slack_user_token", 502)
            scopes = user.get("scope", "") if isinstance(user, dict) else result.get("scope", "")
            granted = frozenset(scopes.split(",")) if isinstance(scopes, str) else frozenset()
            if granted != SLACK_SCOPES:
                raise SlackOAuthError(
                    "slack_oauth_scope_mismatch", 403,
                    None if identity_shape_complete else diagnostic)
            team_id = team.get("id") if isinstance(team, dict) else None
            user_id = user.get("id") if isinstance(user, dict) else None
            # Never ignore a supplied identity conflict while filling a missing
            # field from auth.test.
            if (isinstance(team_id, str)
                    and not hmac.compare_digest(team_id, self.config.team_id)):
                raise SlackOAuthError("slack_oauth_team_mismatch", 403)
            if (isinstance(user_id, str)
                    and not hmac.compare_digest(user_id, self.config.owner_user_id)):
                raise SlackOAuthError("slack_oauth_owner_mismatch", 403)
            if not isinstance(team_id, str) or not isinstance(user_id, str):
                try:
                    identity = self.identity_verifier(token)
                except SlackOAuthError as error:
                    raise SlackOAuthError(error.code, error.status, diagnostic) from None
                team_id = identity.get("team_id")
                user_id = identity.get("user_id")
                if not isinstance(team_id, str) or not isinstance(user_id, str):
                    raise SlackOAuthError(
                        "slack_oauth_identity_verification_failed", 502, diagnostic)
            if (not isinstance(team_id, str)
                    or not hmac.compare_digest(team_id, self.config.team_id)):
                raise SlackOAuthError("slack_oauth_team_mismatch", 403)
            if (not isinstance(user_id, str)
                    or not hmac.compare_digest(user_id, self.config.owner_user_id)):
                raise SlackOAuthError("slack_oauth_owner_mismatch", 403)
            self.store.save_installation(token, int(self.clock()))
            return JSONResponse({"status": "slack_oauth_connected"}, headers={
                "Cache-Control": "no-store", "Pragma": "no-cache",
            })
        except SlackOAuthError as error:
            body: dict[str, Any] = {"error": error.code}
            if error.diagnostic is not None:
                body["diagnostic"] = error.diagnostic
            return JSONResponse(body, status_code=error.status,
                                headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        except Exception:
            return JSONResponse({"error": "slack_oauth_internal_error"}, status_code=500,
                                headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
