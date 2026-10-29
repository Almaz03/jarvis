import io
import json
from pathlib import Path
from urllib.error import URLError
from urllib.parse import parse_qs
import tempfile
import unittest

from stand.__main__ import fixture
from stand.core import Stand, StandError
from stand.telegram_live import (
    STATUS_TEXT,
    TelegramClient,
    TelegramLiveConfig,
    TelegramTransportError,
    TelegramWorker,
)


TOKEN = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890"


class Response:
    def __init__(self, payload):
        self._stream = io.BytesIO(json.dumps(payload).encode())

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size):
        return self._stream.read(size)


class TelegramLiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = TelegramLiveConfig(
            TOKEN, 424242, 424242, Path(self.tmp.name) / "state.sqlite3", 1)
        self.stand = Stand(self.config.stand_config())

    def tearDown(self):
        self.stand.close()
        self.tmp.cleanup()

    def test_live_config_is_explicit_and_validated(self):
        base = {
            "STAND_MODE": "telegram",
            "STAND_ENABLE_LIVE": "true",
            "TELEGRAM_BOT_TOKEN": TOKEN,
            "TELEGRAM_OWNER_USER_ID": "424242",
            "TELEGRAM_OWNER_CHAT_ID": "424242",
            "STAND_STATE_PATH": str(Path(self.tmp.name) / "other.sqlite3"),
        }
        parsed = TelegramLiveConfig.from_env(base)
        self.assertEqual(parsed.owner_chat_id, 424242)
        for key in ("STAND_MODE", "STAND_ENABLE_LIVE", "TELEGRAM_BOT_TOKEN"):
            invalid = dict(base)
            del invalid[key]
            with self.assertRaises(StandError):
                TelegramLiveConfig.from_env(invalid)

    def test_client_uses_fixed_methods_and_sanitizes_errors(self):
        calls = []

        def opener(request, timeout):
            calls.append((request, timeout))
            return Response({"ok": True, "result": []})

        client = TelegramClient(TOKEN, opener)
        self.assertEqual(client.get_updates(17, 1), [])
        request, timeout = calls[0]
        self.assertTrue(request.full_url.endswith("/getUpdates"))
        values = parse_qs(request.data.decode())
        self.assertEqual(values["offset"], ["17"])
        self.assertEqual(timeout, 16)
        with self.assertRaises(TelegramTransportError):
            client._call("deleteWebhook", {}, 1)

        def failing(_request, timeout):
            raise URLError(f"secret {TOKEN} timeout {timeout}")

        with self.assertRaises(TelegramTransportError) as caught:
            TelegramClient(TOKEN, failing).get_me()
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_owner_status_is_acknowledged_once_and_offset_persists(self):
        class FakeClient:
            def __init__(self):
                self.sent = []

            def send_message(self, chat_id, text):
                self.sent.append((chat_id, text))
                return {"message_id": 1}

        client = FakeClient()
        worker = TelegramWorker(self.config, self.stand, client)
        update = fixture()
        update["message"]["text"] = "/status"
        result = worker.process_update(update)
        self.assertTrue(result["accepted"])
        self.assertEqual(client.sent, [(424242, STATUS_TEXT)])
        self.assertEqual(worker.next_offset(), 1002)
        worker.process_update(update)
        self.assertEqual(len(client.sent), 1)

        self.stand.close()
        self.stand = Stand(self.config.stand_config())
        restarted = TelegramWorker(self.config, self.stand, client)
        self.assertEqual(restarted.next_offset(), 1002)

    def test_non_owner_is_rejected_and_never_answered(self):
        class FakeClient:
            def __init__(self):
                self.sent = []

            def send_message(self, *args):
                self.sent.append(args)

        client = FakeClient()
        worker = TelegramWorker(self.config, self.stand, client)
        update = fixture()
        update["message"]["from"]["id"] = 999
        update["message"]["text"] = "/status"
        result = worker.process_update(update)
        self.assertEqual(result["reason"], "owner_mismatch")
        self.assertEqual(client.sent, [])
        self.assertEqual(worker.next_offset(), 1002)


if __name__ == "__main__":
    unittest.main()
