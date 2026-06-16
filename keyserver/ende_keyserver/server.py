from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from ipaddress import ip_address
from typing import Any
from urllib.parse import unquote, urlparse

from .auth import verify_provider_token
from .models import PeerProfile, TokenRecord, _now, hash_token, new_publish_token
from .stores import Store, store_from_env


class KeyserverHandler(BaseHTTPRequestHandler):
    store: Store
    admin_token: str = ""

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/health":
            self._json(HTTPStatus.OK, {"ok": True})
            return
        if path == "/v1/auth/config":
            self._json(HTTPStatus.OK, auth_config_from_env())
            return
        if path.startswith("/v1/peers/"):
            peer_id = _path_id(path, "/v1/peers/")
            profile = self.store.get(peer_id)
            if profile is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "peer not found"})
                return
            self._json(HTTPStatus.OK, profile.to_dict())
            return
        if path.startswith("/v1/share/"):
            peer_id = _path_id(path, "/v1/share/")
            profile = self.store.get(peer_id)
            if profile is None:
                self._json(HTTPStatus.NOT_FOUND, {"error": "peer not found"})
                return
            self._json(HTTPStatus.OK, {"share_code": profile.to_share_code()})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/v1/peers/"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        peer_id = _path_id(path, "/v1/peers/")
        if not self._authorized_peer_write(peer_id):
            return
        try:
            profile = PeerProfile.from_dict(self._read_json(), expected_id=peer_id)
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        self.store.put(profile)
        self._json(HTTPStatus.OK, profile.to_dict())

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not path.startswith("/v1/peers/"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        if not self._authorized():
            return
        deleted = self.store.delete(_path_id(path, "/v1/peers/"))
        self._json(HTTPStatus.OK, {"deleted": deleted})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path.startswith("/v1/auth/"):
            self._handle_auth(_path_id(path, "/v1/auth/"))
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def log_message(self, fmt: str, *args: Any) -> None:
        if os.getenv("ENDE_KEYSERVER_ACCESS_LOG", "").lower() in {"1", "true", "yes"}:
            super().log_message(fmt, *args)

    def _authorized(self) -> bool:
        if not self.admin_token:
            return True
        expected = f"Bearer {self.admin_token}"
        if self.headers.get("Authorization") == expected:
            return True
        self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
        return False

    def _authorized_peer_write(self, peer_id: str) -> bool:
        auth = self.headers.get("Authorization", "")
        if self.admin_token and auth == f"Bearer {self.admin_token}":
            return True
        if not auth.startswith("Bearer "):
            if not self.admin_token and not os.getenv("ENDE_KEYSERVER_REQUIRE_AUTH", ""):
                return True
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return False
        record = self.store.get_token(hash_token(auth.removeprefix("Bearer ")))
        if record is None or not record.active():
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return False
        if record.peer_id != peer_id:
            self._json(HTTPStatus.FORBIDDEN, {"error": "token cannot publish this peer id"})
            return False
        return True

    def _handle_auth(self, provider: str) -> None:
        try:
            body = self._read_json()
            access_token = str(body.get("access_token", "")).strip()
            peer_id = str(body.get("peer_id", "")).strip()
            if not access_token:
                raise ValueError("access_token is required")
            identity = verify_provider_token(provider, access_token, peer_id)
            token = new_publish_token()
            record = TokenRecord(
                token_hash=hash_token(token),
                peer_id=identity.peer_id,
                provider=identity.provider,
                subject=identity.subject,
                email=identity.email,
                created_at=_now(),
            )
            self.store.put_token(record)
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return
        self._json(
            HTTPStatus.OK,
            {
                "token": token,
                "peer_id": record.peer_id,
                "provider": record.provider,
                "subject": record.subject,
            },
        )

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data

    def _json(self, status: HTTPStatus, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def make_handler(store: Store, admin_token: str = "") -> type[KeyserverHandler]:
    class Handler(KeyserverHandler):
        pass

    Handler.store = store
    Handler.admin_token = admin_token
    return Handler


def main() -> None:
    host = os.getenv("ENDE_KEYSERVER_HOST", "127.0.0.1")
    port = int(os.getenv("ENDE_KEYSERVER_PORT", "8765"))
    validate_runtime_config(host)
    handler = make_handler(store_from_env(), os.getenv("ENDE_KEYSERVER_ADMIN_TOKEN", ""))
    server = ThreadingHTTPServer((host, port), handler)
    print(f"ende keyserver listening on http://{host}:{port}")
    server.serve_forever()


def _path_id(path: str, prefix: str) -> str:
    return unquote(path.removeprefix(prefix)).strip()


def validate_runtime_config(host: str) -> None:
    if not _env_enabled("ENDE_KEYSERVER_DEV_AUTH"):
        return
    if _env_enabled("ENDE_KEYSERVER_ALLOW_UNSAFE_DEV_AUTH"):
        return
    if _is_loopback_host(host):
        return
    raise ValueError(
        "ENDE_KEYSERVER_DEV_AUTH requires a loopback bind unless "
        "ENDE_KEYSERVER_ALLOW_UNSAFE_DEV_AUTH=1 is set"
    )


def _env_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized in {"localhost"}:
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def auth_config_from_env() -> dict[str, Any]:
    providers: dict[str, dict[str, str]] = {}
    github_client_id = os.getenv("ENDE_KEYSERVER_GITHUB_CLIENT_ID", "").strip()
    if github_client_id:
        providers["github"] = {"client_id": github_client_id}
    okta_client_id = os.getenv("ENDE_KEYSERVER_OKTA_CLIENT_ID", "").strip()
    okta_issuer = os.getenv("ENDE_KEYSERVER_OKTA_ISSUER", "").strip().rstrip("/")
    if okta_client_id and okta_issuer:
        providers["okta"] = {"client_id": okta_client_id, "issuer": okta_issuer}
    default_provider = os.getenv("ENDE_KEYSERVER_DEFAULT_PROVIDER", "").strip().lower()
    if not default_provider and providers:
        default_provider = next(iter(providers))
    return {"default_provider": default_provider, "providers": providers}
