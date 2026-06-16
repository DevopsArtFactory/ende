from __future__ import annotations

import base64
import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


_ID_RE = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")
_SHARE_PREFIX = "ENDE-PUB-1:"


@dataclass(frozen=True)
class PeerProfile:
    id: str
    recipient: str
    signing_public: str
    display_name: str = ""
    updated_at: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any], *, expected_id: str | None = None) -> "PeerProfile":
        peer_id = str(data.get("id", "")).strip()
        if expected_id is not None and not peer_id:
            peer_id = expected_id
        if expected_id is not None and peer_id != expected_id:
            raise ValueError("profile id does not match request path")
        if not _ID_RE.match(peer_id):
            raise ValueError("id must be 1-128 chars and contain only letters, numbers, '.', '_', ':', '@', '-'")

        recipient = str(data.get("recipient", "")).strip()
        if not recipient.startswith("age1"):
            raise ValueError("recipient must be an age public key")

        signing_public = str(data.get("signing_public", "")).strip()
        _validate_ed25519_public(signing_public)

        display_name = str(data.get("display_name", "")).strip()
        updated_at = str(data.get("updated_at", "")).strip() or _now()

        return cls(
            id=peer_id,
            recipient=recipient,
            signing_public=signing_public,
            display_name=display_name,
            updated_at=updated_at,
        )

    def to_dict(self) -> dict[str, str]:
        data = {
            "id": self.id,
            "recipient": self.recipient,
            "signing_public": self.signing_public,
            "updated_at": self.updated_at,
        }
        if self.display_name:
            data["display_name"] = self.display_name
        return data

    def to_share_code(self) -> str:
        import json

        payload = {
            "version": 1,
            "id": self.id,
            "recipient": self.recipient,
            "signing_public": self.signing_public,
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode()
        return _SHARE_PREFIX + encoded.rstrip("=")


@dataclass(frozen=True)
class TokenRecord:
    token_hash: str
    peer_id: str
    provider: str
    subject: str
    email: str = ""
    created_at: str = ""
    revoked_at: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenRecord":
        return cls(
            token_hash=str(data.get("token_hash", "")).strip(),
            peer_id=str(data.get("peer_id", "")).strip(),
            provider=str(data.get("provider", "")).strip(),
            subject=str(data.get("subject", "")).strip(),
            email=str(data.get("email", "")).strip(),
            created_at=str(data.get("created_at", "")).strip(),
            revoked_at=str(data.get("revoked_at", "")).strip(),
        )

    def to_dict(self) -> dict[str, str]:
        data = {
            "token_hash": self.token_hash,
            "peer_id": self.peer_id,
            "provider": self.provider,
            "subject": self.subject,
            "created_at": self.created_at,
        }
        if self.email:
            data["email"] = self.email
        if self.revoked_at:
            data["revoked_at"] = self.revoked_at
        return data

    def active(self) -> bool:
        return self.revoked_at == ""


def new_publish_token() -> str:
    return "ende_ks_" + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def _validate_ed25519_public(value: str) -> None:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("signing_public must be base64") from exc
    if len(raw) != 32:
        raise ValueError("signing_public must be a 32-byte Ed25519 public key")


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
