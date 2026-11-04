import base64
import os
import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from stand.core import Config, Stand, StandError
from stand.slack_oauth import SlackOAuthConfig, SlackOAuthService


APP_ID = "A0CFN4GD8L8"
TEAM_ID = "T039VA2H3V5"
OWNER_ID = "U0123456789"
DM_ID = "D0C7SAYJB24"
CLIENT_ID = "1234567890.1234567890"
CLIENT_SECRET = "c" * 32
SETUP_TOKEN = "s" * 40
KEY = b"k" * 32
USER_TOKEN = "xoxp-" + "t" * 40


def config() -> SlackOAuthConfig:
    return SlackOAuthConfig(APP_ID, TEAM_ID, OWNER_ID, DM_ID, CLIENT_ID,
                            CLIENT_SECRET, SETUP_TOKEN, KEY)


class SlackOAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.stand = Stand(Config(424242, 424242, Path(self.tmp.name) / "state.sqlite3"))
        self.now = 1_800_000_000
        self.exchange_calls = []
        self.identity_calls = []

        def exchange(_config, code):
            self.exchange_calls.append(code)
            return {"ok": True, "access_token": USER_TOKEN, "token_type": "user",
                    "authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history"},
                    "team": {"id": TEAM_ID}}

        def verify_identity(token):
            self.identity_calls.append(token)
            return {"ok": True, "team_id": TEAM_ID, "user_id": OWNER_ID}

        self.service = SlackOAuthService(config(), self.stand.db, self.stand.db_lock,
                                         exchange, verify_identity, lambda: self.now)
        from starlette.applications import Starlette
        from starlette.routing import Route
        self.client = TestClient(Starlette(routes=[
            Route("/slack/oauth/start", self.service.start, methods=["POST"]),
            Route("/slack/oauth/callback", self.service.callback, methods=["GET"]),
        ]))

    def tearDown(self) -> None:
        self.stand.close()
        self.tmp.cleanup()

    def start(self):
        response = self.client.post("/slack/oauth/start",
                                    headers={"Authorization": "Bearer " + SETUP_TOKEN})
        self.assertEqual(response.status_code, 200)
        from urllib.parse import parse_qs, urlsplit
        url = response.json()["authorization_url"]
        query = parse_qs(urlsplit(url).query)
        return url, query["state"][0]

    def test_start_requires_setup_bearer_and_exact_scopes(self) -> None:
        denied = self.client.post("/slack/oauth/start")
        self.assertEqual(denied.status_code, 401)
        url, _state = self.start()
        self.assertIn("slack.com/oauth/v2_user/authorize", url)
        self.assertIn("scope=chat%3Awrite%2Cim%3Ahistory", url)
        self.assertIn("team=" + TEAM_ID, url)
        self.assertEqual(denied.headers["cache-control"], "no-store")

    def test_valid_callback_encrypts_token_and_state_is_one_time(self) -> None:
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 200)
        row = self.stand.db.execute("SELECT * FROM slack_installation").fetchone()
        self.assertEqual(row["team_id"], TEAM_ID)
        self.assertEqual(row["owner_user_id"], OWNER_ID)
        self.assertNotIn(USER_TOKEN, row["token_ciphertext"])
        self.assertNotIn(USER_TOKEN, response.text)
        replay = self.client.get("/slack/oauth/callback",
                                 params={"state": state, "code": "code.1234567890"})
        self.assertEqual(replay.status_code, 400)
        self.assertEqual(len(self.exchange_calls), 1)

    def test_standard_v2_nested_user_grant_is_accepted(self) -> None:
        nested_token = "xoxp-" + "n" * 40
        self.service.exchanger = lambda _config, _code: {
            "ok": True,
            "access_token": "xoxb-" + "b" * 40,
            "token_type": "bot",
            "authed_user": {
                "id": OWNER_ID,
                "scope": "chat:write,im:history",
                "access_token": nested_token,
                "token_type": "user",
            },
            "team": {"id": TEAM_ID},
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 200)
        row = self.stand.db.execute("SELECT * FROM slack_installation").fetchone()
        self.assertIsNotNone(row)
        self.assertNotIn(nested_token, row["token_ciphertext"])

    def test_nested_non_user_grant_fails_even_with_top_level_user(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True,
            "access_token": USER_TOKEN,
            "token_type": "user",
            "authed_user": {
                "id": OWNER_ID,
                "scope": "chat:write,im:history",
                "access_token": "xoxb-" + "b" * 40,
                "token_type": "bot",
            },
            "team": {"id": TEAM_ID},
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "slack_oauth_token_type_mismatch")
        self.assertEqual(response.json()["diagnostic"]["selected_grant_location"], "nested")
        self.assertEqual(response.json()["diagnostic"]["selected_token_type"],
                         "documented_bot")
        count = self.stand.db.execute("SELECT COUNT(*) FROM slack_installation").fetchone()[0]
        self.assertEqual(count, 0)

    def test_bearer_or_missing_type_requires_auth_test(self) -> None:
        for token_type in ("Bearer", None):
            with self.subTest(token_type=token_type):
                self.identity_calls.clear()
                result = {
                    "ok": True, "access_token": USER_TOKEN,
                    "authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history"},
                    "team": {"id": TEAM_ID},
                }
                if token_type is not None:
                    result["token_type"] = token_type
                self.service.exchanger = lambda _config, _code, value=result: value
                _url, state = self.start()
                response = self.client.get(
                    "/slack/oauth/callback",
                    params={"state": state, "code": "code.1234567890"})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(self.identity_calls, [USER_TOKEN])
                self.assertEqual(self.service.store.config.team_id, TEAM_ID)

    def test_auth_test_bot_identity_is_rejected_for_bearer(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "Bearer",
            "authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history"},
            "team": {"id": TEAM_ID},
        }
        self.service.identity_verifier = lambda _token: {
            "ok": True, "team_id": TEAM_ID, "user_id": OWNER_ID,
            "bot_id": "B0123456789",
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 403)
        body = response.json()
        self.assertEqual(body["error"], "slack_oauth_token_type_mismatch")
        self.assertEqual(body["diagnostic"]["selected_token_type"], "oauth_bearer")
        self.assertNotIn("B0123456789", response.text)

    def test_unknown_token_type_is_categorized_without_echoing_it(self) -> None:
        raw_type = "unexpected-private-type"
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": raw_type,
            "authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history"},
            "team": {"id": TEAM_ID},
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 403)
        body = response.json()
        self.assertEqual(body["error"], "slack_oauth_token_type_mismatch")
        self.assertEqual(body["diagnostic"]["selected_token_type"], "other_string")
        self.assertNotIn(raw_type, response.text)
        self.assertEqual(self.identity_calls, [])

    def test_partial_nested_metadata_does_not_select_top_level_bot_or_empty_token(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "user",
            "authed_user": {
                "id": OWNER_ID, "scope": "chat:write,im:history",
                "token_type": "bot",
            },
            "team": {"id": TEAM_ID},
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.identity_calls, [])

    def test_expired_state_does_not_exchange(self) -> None:
        _url, state = self.start()
        self.now += 601
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.exchange_calls, [])

    def test_wrong_owner_team_scope_or_token_fails_closed(self) -> None:
        mutations = [
            ({"team": {"id": "T9999999999"}}, "slack_oauth_team_mismatch", 403),
            ({"authed_user": {"id": "U9999999999", "scope": "chat:write,im:history"}},
             "slack_oauth_owner_mismatch", 403),
            ({"authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history,im:read"}},
             "slack_oauth_scope_mismatch", 403),
            ({"access_token": "not-a-token"}, "invalid_slack_user_token", 502),
        ]
        for mutation, error, status in mutations:
            with self.subTest(mutation=mutation):
                _url, state = self.start()
                base = {"ok": True, "access_token": USER_TOKEN, "token_type": "user",
                        "authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history"},
                        "team": {"id": TEAM_ID}}
                base.update(mutation)
                self.service.exchanger = lambda _config, _code, result=base: result
                response = self.client.get("/slack/oauth/callback",
                                           params={"state": state, "code": "code.1234567890"})
                self.assertEqual(response.status_code, status)
                self.assertEqual(response.json()["error"], error)
                self.assertNotIn("not-a-token", response.text)
                count = self.stand.db.execute("SELECT COUNT(*) FROM slack_installation").fetchone()[0]
                self.assertEqual(count, 0)

    def test_missing_identity_objects_are_verified_with_auth_test(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "user",
            "scope": "chat:write,im:history", "team": None, "authed_user": None,
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.identity_calls, [USER_TOKEN])
        row = self.stand.db.execute("SELECT * FROM slack_installation").fetchone()
        self.assertEqual(row["team_id"], TEAM_ID)
        self.assertEqual(row["owner_user_id"], OWNER_ID)

    def test_identity_fallback_keeps_owner_and_team_checks(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "user",
            "scope": "chat:write,im:history", "team": None, "authed_user": None,
        }
        for identity, expected in (
            ({"ok": True, "team_id": "T9999999999", "user_id": OWNER_ID},
             "slack_oauth_team_mismatch"),
            ({"ok": True, "team_id": TEAM_ID, "user_id": "U9999999999"},
             "slack_oauth_owner_mismatch"),
        ):
            with self.subTest(expected=expected):
                self.service.identity_verifier = lambda _token, value=identity: value
                _url, state = self.start()
                response = self.client.get("/slack/oauth/callback",
                                           params={"state": state, "code": "code.1234567890"})
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json(), {"error": expected})
        count = self.stand.db.execute("SELECT COUNT(*) FROM slack_installation").fetchone()[0]
        self.assertEqual(count, 0)

    def test_fallback_never_overrides_a_supplied_identity_conflict(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "user",
            "scope": "chat:write,im:history",
            "team": {"id": "T9999999999"}, "authed_user": None,
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"error": "slack_oauth_team_mismatch"})
        self.assertEqual(self.identity_calls, [])

    def test_shape_diagnostic_contains_only_allowlisted_type_categories(self) -> None:
        secret = "raw-secret-that-must-not-leak"
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "user",
            "scope": "chat:write,im:history", "team": None,
            "authed_user": None, "unexpected": secret,
            "team_id": TEAM_ID, "user_id": OWNER_ID,
        }
        self.service.identity_verifier = lambda _token: {"ok": True}
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 502)
        body = response.json()
        self.assertEqual(body["error"], "slack_oauth_identity_verification_failed")
        self.assertEqual(set(body["diagnostic"]), {
            "team", "authed_user", "team_id", "authed_user_id",
            "authed_user_scope", "authed_user_access_token",
            "authed_user_token_type", "top_level_scope",
            "top_level_access_token", "top_level_token_type",
            "top_level_team_id", "top_level_user_id",
            "selected_grant_location", "selected_token_type",
            "selected_access_token",
        })
        self.assertTrue(set(body["diagnostic"].values()) <= {
            "missing", "null", "object", "string", "other", "unavailable",
            "nested", "top_level", "missing_or_null", "other_type",
            "expected_user", "documented_bot", "oauth_bearer", "other_string",
            "user_token_pattern", "bot_token_pattern",
        })
        self.assertNotIn(secret, response.text)
        self.assertNotIn(TEAM_ID, response.text)
        self.assertNotIn(OWNER_ID, response.text)
        self.assertNotIn(USER_TOKEN, response.text)
        self.assertNotIn("unexpected", response.text)

    def test_env_is_disabled_by_default_and_relay_fails_closed(self) -> None:
        self.assertIsNone(SlackOAuthConfig.from_env({}))
        with self.assertRaisesRegex(StandError, "slack_relay_not_implemented"):
            SlackOAuthConfig.from_env({"SLACK_RELAY_ENABLED": "true"})

    def test_enabled_env_requires_exact_binding_and_key(self) -> None:
        env = {
            "SLACK_OAUTH_ENABLED": "true", "SLACK_RELAY_ENABLED": "false",
            "SLACK_APP_ID": APP_ID, "SLACK_TEAM_ID": TEAM_ID,
            "SLACK_OWNER_USER_ID": OWNER_ID, "SLACK_TARGET_DM_ID": DM_ID,
            "SLACK_CLIENT_ID": CLIENT_ID, "SLACK_CLIENT_SECRET": CLIENT_SECRET,
            "SLACK_OAUTH_SETUP_TOKEN": SETUP_TOKEN,
            "SLACK_TOKEN_ENCRYPTION_KEY": base64.urlsafe_b64encode(KEY).decode("ascii"),
        }
        self.assertEqual(SlackOAuthConfig.from_env(env), config())
        env["SLACK_TEAM_ID"] = "T9999999999"
        with self.assertRaisesRegex(StandError, "fixed_slack_team_id_required"):
            SlackOAuthConfig.from_env(env)


if __name__ == "__main__":
    unittest.main()
