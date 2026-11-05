import base64
import tempfile
import unittest
from pathlib import Path

from stand.core import Config, Stand, StandError
from stand.slack_oauth import SlackOAuthConfig, SlackOAuthStore
from stand.slack_relay import (
    OneTimeSlackRelayTest,
    SLACK_DOT_BOT_ID,
    SLACK_RELAY_TEST_APPROVAL,
    SLACK_RELAY_TEST_TEXT,
    SLACK_TARGET_DM_ID,
    SlackRelayTestConfig,
    SlackTransportError,
    build_one_time_test,
)


APP_ID = "A0CFN4GD8L8"
TEAM_ID = "T039VA2H3V5"
OWNER_ID = "U0123456789"
CLIENT_ID = "1234567890.1234567890"
CLIENT_SECRET = "c" * 32
SETUP_TOKEN = "s" * 40
KEY = b"k" * 32
USER_TOKEN = "xoxp-" + "t" * 40


def oauth_config() -> SlackOAuthConfig:
    return SlackOAuthConfig(APP_ID, TEAM_ID, OWNER_ID, SLACK_TARGET_DM_ID,
                            CLIENT_ID, CLIENT_SECRET, SETUP_TOKEN, KEY)


class FakeSlack:
    def __init__(self, messages=None, post_error=False, reply=True):
        self.messages = list(messages or [])
        self.post_error = post_error
        self.reply = reply
        self.post_calls = 0
        self.history_calls = 0

    def history(self, oldest, cursor=""):
        self.history_calls += 1
        self.assertable_oldest = oldest
        return ([m for m in self.messages if m.get("ts", "") >= oldest], "")

    def post_test_message(self):
        self.post_calls += 1
        if self.post_error:
            raise SlackTransportError("slack_request_failed")
        timestamp = "1800000010.000001"
        self.messages.append({
            "type": "message", "user": OWNER_ID,
            "text": SLACK_RELAY_TEST_TEXT, "ts": timestamp,
        })
        if self.reply:
            self.messages.append({
                "type": "message", "bot_id": SLACK_DOT_BOT_ID,
                "text": "OK", "ts": "1800000011.000001",
            })
        return timestamp


class SlackRelayTestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.stand = Stand(Config(
            424242, 424242, Path(self.tmp.name) / "state.sqlite3"))
        self.oauth = oauth_config()
        SlackOAuthStore(self.stand.db, self.stand.db_lock, self.oauth).save_installation(
            USER_TOKEN, 1_800_000_000)

    def tearDown(self):
        self.stand.close()
        self.tmp.cleanup()

    def worker(self, client):
        return OneTimeSlackRelayTest(
            self.stand.db, self.stand.db_lock, self.oauth, client,
            clock=lambda: 1_800_000_000, sleeper=lambda _delay: None)

    def test_sends_fixed_message_once_and_matches_only_fixed_dot(self):
        client = FakeSlack()
        result = self.worker(client).run(wait_seconds=0)
        self.assertEqual(result, {
            "status": "reply_verified",
            "slack_ts": "1800000010.000001",
            "reply_ts": "1800000011.000001",
            "duplicate_prevented": False,
        })
        self.assertEqual(client.post_calls, 1)
        self.assertEqual(client.messages[0]["text"], SLACK_RELAY_TEST_TEXT)

        repeated = self.worker(client).run(wait_seconds=0)
        self.assertEqual(repeated["status"], "reply_verified")
        self.assertEqual(client.post_calls, 1)

    def test_recent_existing_owner_test_prevents_send(self):
        client = FakeSlack(messages=[{
            "type": "message", "user": OWNER_ID,
            "text": SLACK_RELAY_TEST_TEXT, "ts": "1800000001.000001",
        }, {
            "type": "message", "bot_id": SLACK_DOT_BOT_ID,
            "text": "OK", "ts": "1800000002.000001",
        }], reply=False)
        result = self.worker(client).run(wait_seconds=0)
        self.assertEqual(result["status"], "reply_verified")
        self.assertTrue(result["duplicate_prevented"])
        self.assertEqual(client.post_calls, 0)

    def test_uncertain_send_is_never_retried(self):
        first_client = FakeSlack(post_error=True)
        first = self.worker(first_client).run(wait_seconds=0)
        self.assertEqual(first, {"status": "send_uncertain", "duplicate_prevented": True})
        self.assertEqual(first_client.post_calls, 1)

        second_client = FakeSlack(reply=False)
        second = self.worker(second_client).run(wait_seconds=0)
        self.assertEqual(second, {"status": "send_uncertain", "duplicate_prevented": True})
        self.assertEqual(second_client.post_calls, 0)

    def test_unrelated_messages_are_not_reported_or_matched(self):
        secret_text = "other private message"
        client = FakeSlack(messages=[{
            "type": "message", "bot_id": "B9999999999",
            "text": "OK", "ts": "1800000011.000001",
        }, {
            "type": "message", "bot_id": SLACK_DOT_BOT_ID,
            "text": secret_text, "ts": "1800000012.000001",
        }], reply=False)
        result = self.worker(client).run(wait_seconds=0)
        self.assertEqual(result["status"], "sent_no_reply_yet")
        self.assertNotIn(secret_text, str(result))

    def test_build_decrypts_bound_token_only_for_client_factory(self):
        captured = []
        fake = FakeSlack(reply=False)

        def factory(token):
            captured.append(token)
            return fake

        config = SlackRelayTestConfig(self.oauth, SLACK_RELAY_TEST_APPROVAL)
        worker = build_one_time_test(
            self.stand.db, self.stand.db_lock, config, factory,
            clock=lambda: 1_800_000_000, sleeper=lambda _delay: None)
        result = worker.run(wait_seconds=0)
        self.assertEqual(captured, [USER_TOKEN])
        self.assertNotIn(USER_TOKEN, str(result))
        row = self.stand.db.execute(
            "SELECT token_ciphertext FROM slack_installation").fetchone()
        self.assertNotIn(USER_TOKEN, row[0])

    def test_ephemeral_exact_approval_is_required_and_relay_stays_off(self):
        env = {
            "SLACK_OAUTH_ENABLED": "true", "SLACK_RELAY_ENABLED": "false",
            "SLACK_APP_ID": APP_ID, "SLACK_TEAM_ID": TEAM_ID,
            "SLACK_OWNER_USER_ID": OWNER_ID, "SLACK_TARGET_DM_ID": SLACK_TARGET_DM_ID,
            "SLACK_CLIENT_ID": CLIENT_ID, "SLACK_CLIENT_SECRET": CLIENT_SECRET,
            "SLACK_OAUTH_SETUP_TOKEN": SETUP_TOKEN,
            "SLACK_TOKEN_ENCRYPTION_KEY": base64.urlsafe_b64encode(KEY).decode("ascii"),
        }
        with self.assertRaisesRegex(StandError, "explicit_slack_relay_test_approval_required"):
            SlackRelayTestConfig.from_env(env)
        env["SLACK_RELAY_TEST_APPROVAL"] = SLACK_RELAY_TEST_APPROVAL
        self.assertEqual(SlackRelayTestConfig.from_env(env).oauth, self.oauth)


if __name__ == "__main__":
    unittest.main()
