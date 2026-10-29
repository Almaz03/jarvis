import base64
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from stand.__main__ import fixture
from stand.mcp_live import (Auth0Verifier, LiveConfig, MCPError, Principal, PROTOCOL,
                            create_app, validate_callback_url, webhook_signature)


TOKEN = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890"


class FakeTelegram:
    def __init__(self):
        self.sent = []

    def send_message(self, chat_id, text):
        self.sent.append((chat_id, text))
        return {"message_id": 1}


class SigningKey:
    def __init__(self, key):
        self.key = key


class JWKS:
    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, _token):
        return SigningKey(self.key)


class MCPLiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = LiveConfig("dev-example.us.auth0.com", "https://jarvis.akalmaz.tech",
            "auth0|owner", "https://jarvis.akalmaz.tech", Path(self.tmp.name) / "state.sqlite3",
            424242, 424242, TOKEN)
        self.telegram = FakeTelegram()

        def verifier(token):
            if token != "owner-token":
                raise MCPError(-32001, "Unauthorized", 401)
            return Principal("auth0|owner", frozenset({"telegram:read", "telegram:reply", "telegram:events"}))

        self.app = create_app(self.config, verifier, self.telegram)
        self.client = TestClient(self.app)

    def tearDown(self):
        self.app.state.service.store.close()
        self.tmp.cleanup()

    @staticmethod
    def params(**values):
        values["_meta"] = {"io.modelcontextprotocol/protocolVersion": PROTOCOL,
                           "io.modelcontextprotocol/clientCapabilities": {}}
        return values

    def rpc(self, method, params=None, **headers):
        defaults = {"Authorization": "Bearer owner-token", "MCP-Protocol-Version": PROTOCOL,
                    "Mcp-Method": method, "Accept": "application/json, text/event-stream"}
        defaults.update(headers)
        return self.client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": method,
                                               "params": params or self.params()}, headers=defaults)

    def test_metadata_and_protocol_validation(self):
        metadata = self.client.get("/.well-known/oauth-protected-resource").json()
        self.assertEqual(metadata["resource"], self.config.audience)
        self.assertEqual(self.rpc("server/discover").status_code, 200)
        missing_accept = self.rpc("server/discover", Accept="application/json")
        self.assertEqual(missing_accept.status_code, 400)
        mismatch = self.rpc("server/discover", self.params(), **{"MCP-Protocol-Version": "1900-01-01"})
        self.assertEqual(mismatch.json()["error"]["code"], -32020)
        unsupported = self.params()
        unsupported["_meta"]["io.modelcontextprotocol/protocolVersion"] = "1900-01-01"
        response = self.rpc("server/discover", unsupported, **{"MCP-Protocol-Version": "1900-01-01"})
        self.assertEqual(response.json()["error"]["code"], -32022)

    def test_tools_read_and_reply_only_to_stored_owner_chat(self):
        result = self.app.state.service.store.stand.ingest(fixture())
        ref = result["message_ref"]
        read = self.rpc("tools/call", self.params(name="read_telegram_message",
                        arguments={"message_ref": ref}), **{"Mcp-Name": "read_telegram_message"})
        self.assertEqual(read.status_code, 200, read.text)
        self.assertTrue(read.json()["result"]["structuredContent"]["untrusted"])
        reply = self.rpc("tools/call", self.params(name="reply_to_telegram_message",
                         arguments={"message_ref": ref, "text": "hi", "idempotency_key": "one"}),
                         **{"Mcp-Name": "reply_to_telegram_message"})
        self.assertEqual(reply.json()["result"]["structuredContent"]["status"], "sent")
        self.assertEqual(self.telegram.sent, [(424242, "hi")])
        injected = self.rpc("tools/call", self.params(name="reply_to_telegram_message",
                            arguments={"message_ref": ref, "text": "x", "idempotency_key": "two",
                                       "chat_id": 999}), **{"Mcp-Name": "reply_to_telegram_message"})
        self.assertEqual(injected.json()["error"]["code"], -32602)
        self.assertEqual(len(self.telegram.sent), 1)

    def test_scope_rejection(self):
        service = self.app.state.service
        principal = Principal("auth0|owner", frozenset({"telegram:read"}))
        with self.assertRaises(MCPError) as caught:
            service.dispatch(principal, "events/list", self.params(), None)
        self.assertEqual(caught.exception.http_status, 403)

    def test_auth0_exact_owner_sub_and_claims(self):
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        verifier = Auth0Verifier(self.config)
        verifier.jwks = JWKS(private.public_key())

        def token(sub="auth0|owner", audience=None, issuer=None):
            now = int(time.time())
            return jwt.encode({"sub": sub, "aud": audience or self.config.audience,
                               "iss": issuer or "https://dev-example.us.auth0.com/",
                               "iat": now, "exp": now + 300,
                               "scope": "telegram:read telegram:reply telegram:events"},
                              private, algorithm="RS256", headers={"kid": "test"})

        self.assertEqual(verifier(token()).subject, "auth0|owner")
        for bad in (token(sub="auth0|other"), token(audience="https://other.invalid"),
                    token(issuer="https://other.invalid/")):
            with self.assertRaises(MCPError):
                verifier(bad)

    def test_ssrf_and_standard_webhook_signature(self):
        private_answers = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("stand.mcp_live.socket.getaddrinfo", return_value=private_answers):
            with self.assertRaises(MCPError):
                validate_callback_url("https://callback.example/test")
        secret_bytes = b"a" * 32
        secret = "whsec_" + base64.b64encode(secret_bytes).decode()
        expected = base64.b64encode(__import__("hmac").new(
            secret_bytes, b"evt_1.123.{\"ok\":true}", __import__("hashlib").sha256).digest()).decode()
        self.assertEqual(webhook_signature(secret, "evt_1", "123", b'{"ok":true}'), "v1," + expected)

    def test_event_payload_is_thin_and_delivery_is_persistent(self):
        result = self.app.state.service.store.stand.ingest(fixture())
        now = int(time.time())
        secret = "whsec_" + base64.b64encode(b"b" * 32).decode()
        db = self.app.state.service.store.stand.db
        with db:
            db.execute("INSERT INTO subscriptions VALUES (?,?,?,?,?,1,?,?)",
                       ("sub_test", "auth0|owner", "telegram.message.created",
                        "https://callback.example/hook", secret, now, now + 300))
        seen = []

        def deliver(url, signing_secret, event_id, body, subscription_id=None, connector=None):
            seen.append((url, signing_secret, event_id, json.loads(body), subscription_id))
            return 204, b""

        with patch("stand.mcp_live.signed_post", side_effect=deliver):
            self.assertEqual(self.app.state.service.deliver_once(), 1)
            self.assertEqual(self.app.state.service.deliver_once(), 0)
        payload = seen[0][3]
        self.assertEqual(payload["data"]["message_ref"], result["message_ref"])
        self.assertNotIn(fixture()["message"]["text"], json.dumps(payload))
        self.assertEqual(db.execute("SELECT status FROM deliveries").fetchone()[0], "delivered")


if __name__ == "__main__":
    unittest.main()
