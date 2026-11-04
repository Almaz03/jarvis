import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "slack-app-manifest.json"


class SlackAppManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    def test_requests_only_required_user_scopes(self) -> None:
        scopes = self.manifest["oauth_config"]["scopes"]
        self.assertEqual(scopes, {"user": ["chat:write", "im:history"]})

    def test_is_not_org_wide_and_has_no_live_transport(self) -> None:
        settings = self.manifest["settings"]
        self.assertFalse(settings["org_deploy_enabled"])
        self.assertFalse(settings["socket_mode_enabled"])
        self.assertNotIn("event_subscriptions", settings)
        self.assertNotIn("incoming_webhooks", settings)

    def test_has_only_the_expected_https_redirect(self) -> None:
        self.assertEqual(
            self.manifest["oauth_config"]["redirect_urls"],
            ["https://jarvis.akalmaz.tech/slack/oauth/callback"],
        )

    def test_contains_no_secrets_or_tokens(self) -> None:
        raw = MANIFEST_PATH.read_text(encoding="utf-8").lower()
        forbidden = ("client_secret", "signing_secret", "xoxp-", "xoxb-")
        for marker in forbidden:
            self.assertNotIn(marker, raw)


if __name__ == "__main__":
    unittest.main()
