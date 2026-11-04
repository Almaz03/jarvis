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

        def exchange(_config, code):
            self.exchange_calls.append(code)
            return {"ok": True, "access_token": USER_TOKEN, "token_type": "user",
                    "authed_user": {"id": OWNER_ID, "scope": "chat:write,im:history"},
                    "team": {"id": TEAM_ID}}

        self.service = SlackOAuthService(config(), self.stand.db, self.stand.db_lock,
                                         exchange, lambda: self.now)
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
        self.assertEqual(response.json(), {"error": "slack_oauth_token_type_mismatch"})
        count = self.stand.db.execute("SELECT COUNT(*) FROM slack_installation").fetchone()[0]
        self.assertEqual(count, 0)

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
                self.assertEqual(response.json(), {"error": error})
                count = self.stand.db.execute("SELECT COUNT(*) FROM slack_installation").fetchone()[0]
                self.assertEqual(count, 0)

    def test_missing_identity_objects_reports_shape_only(self) -> None:
        self.service.exchanger = lambda _config, _code: {
            "ok": True, "access_token": USER_TOKEN, "token_type": "user",
            "team": None, "authed_user": None,
        }
        _url, state = self.start()
        response = self.client.get("/slack/oauth/callback",
                                   params={"state": state, "code": "code.1234567890"})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json(), {"error": "slack_oauth_response_shape_mismatch"})
        self.assertNotIn(TEAM_ID, response.text)
        self.assertNotIn(OWNER_ID, response.text)

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
