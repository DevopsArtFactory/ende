import base64
import json
import os
import unittest
from http import HTTPStatus
from http.client import HTTPConnection
from threading import Thread
from unittest.mock import patch

import keyserver.ende_keyserver.server as keyserver_server
from keyserver.ende_keyserver.auth import ProviderIdentity
from keyserver.ende_keyserver.server import make_handler
from keyserver.ende_keyserver.stores import MemoryStore


SIGNING_PUBLIC = base64.b64encode(b"a" * 32).decode()


class KeyserverTest(unittest.TestCase):
    def setUp(self):
        handler = make_handler(MemoryStore(), "secret")
        from http.server import ThreadingHTTPServer

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def request(self, method, path, body=None, token=None):
        conn = HTTPConnection(self.host, self.port, timeout=5)
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is not None:
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = json.loads(resp.read().decode())
        conn.close()
        return resp.status, data

    def test_put_get_and_share_code(self):
        profile = {
            "id": "alice",
            "recipient": "age1example",
            "signing_public": SIGNING_PUBLIC,
            "display_name": "Alice",
        }
        status, body = self.request("PUT", "/v1/peers/alice", profile, token="secret")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["id"], "alice")

        status, body = self.request("GET", "/v1/peers/alice")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(body["recipient"], "age1example")

        status, body = self.request("GET", "/v1/share/alice")
        self.assertEqual(status, HTTPStatus.OK)
        self.assertTrue(body["share_code"].startswith("ENDE-PUB-1:"))
        payload = body["share_code"].removeprefix("ENDE-PUB-1:")
        payload += "=" * (-len(payload) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload).decode())
        self.assertEqual(decoded["version"], 1)
        self.assertEqual(decoded["id"], "alice")
        self.assertEqual(decoded["recipient"], "age1example")
        self.assertEqual(decoded["signing_public"], SIGNING_PUBLIC)

    def test_write_requires_bearer_token(self):
        profile = {
            "id": "alice",
            "recipient": "age1example",
            "signing_public": SIGNING_PUBLIC,
        }
        status, body = self.request("PUT", "/v1/peers/alice", profile)
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(body["error"], "unauthorized")

    def test_invalid_profile_rejected(self):
        status, body = self.request(
            "PUT",
            "/v1/peers/alice",
            {"id": "bob", "recipient": "not-age", "signing_public": "nope"},
            token="secret",
        )
        self.assertEqual(status, HTTPStatus.BAD_REQUEST)
        self.assertIn("id", body["error"])

    def test_sso_token_can_publish_only_own_peer_id(self):
        original = keyserver_server.verify_provider_token
        keyserver_server.verify_provider_token = lambda provider, token, peer_id: ProviderIdentity(
            provider=provider,
            subject="alice",
            peer_id=peer_id,
            email="alice@example.com",
        )
        try:
            status, body = self.request(
                "POST",
                "/v1/auth/github",
                {"access_token": "provider-token", "peer_id": "alice"},
            )
        finally:
            keyserver_server.verify_provider_token = original
        self.assertEqual(status, HTTPStatus.OK)
        token = body["token"]

        profile = {
            "id": "alice",
            "recipient": "age1example",
            "signing_public": SIGNING_PUBLIC,
        }
        status, _ = self.request("PUT", "/v1/peers/alice", profile, token=token)
        self.assertEqual(status, HTTPStatus.OK)

        bob = dict(profile)
        bob["id"] = "bob"
        status, body = self.request("PUT", "/v1/peers/bob", bob, token=token)
        self.assertEqual(status, HTTPStatus.FORBIDDEN)
        self.assertIn("token cannot publish", body["error"])


class RuntimeConfigTest(unittest.TestCase):
    def test_dev_auth_rejects_non_loopback_bind_without_override(self):
        env = {"ENDE_KEYSERVER_DEV_AUTH": "1"}
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaisesRegex(ValueError, "loopback bind"):
                keyserver_server.validate_runtime_config("0.0.0.0")

    def test_dev_auth_allows_loopback_bind(self):
        env = {"ENDE_KEYSERVER_DEV_AUTH": "1"}
        with patch.dict(os.environ, env, clear=True):
            keyserver_server.validate_runtime_config("127.0.0.1")

    def test_dev_auth_allows_explicit_unsafe_override(self):
        env = {
            "ENDE_KEYSERVER_DEV_AUTH": "1",
            "ENDE_KEYSERVER_ALLOW_UNSAFE_DEV_AUTH": "1",
        }
        with patch.dict(os.environ, env, clear=True):
            keyserver_server.validate_runtime_config("0.0.0.0")


if __name__ == "__main__":
    unittest.main()
