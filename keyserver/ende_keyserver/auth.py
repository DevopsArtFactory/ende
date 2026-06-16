from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderIdentity:
    provider: str
    subject: str
    peer_id: str
    email: str = ""


def verify_provider_token(provider: str, access_token: str, requested_peer_id: str = "") -> ProviderIdentity:
    provider = provider.strip().lower()
    if os.getenv("ENDE_KEYSERVER_DEV_AUTH", "").lower() in {"1", "true", "yes"}:
        return _verify_dev(provider, access_token, requested_peer_id)
    if provider == "github":
        return _verify_github(access_token, requested_peer_id)
    if provider == "okta":
        return _verify_okta(access_token, requested_peer_id)
    raise ValueError(f"unsupported auth provider: {provider}")


def _verify_dev(provider: str, access_token: str, requested_peer_id: str) -> ProviderIdentity:
    subject = access_token.removeprefix("dev:").strip()
    if not subject:
        subject = requested_peer_id.strip()
    if not subject:
        raise ValueError("dev auth token must include a subject")
    peer_id = _resolve_peer_id(provider, subject, "", requested_peer_id)
    return ProviderIdentity(provider=provider, subject=subject, peer_id=peer_id)


def _verify_github(access_token: str, requested_peer_id: str) -> ProviderIdentity:
    user = _get_json(
        "https://api.github.com/user",
        {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "ende-keyserver",
        },
    )
    login = str(user.get("login", "")).strip()
    if not login:
        raise ValueError("github token did not return a login")
    email = str(user.get("email", "") or "").strip()
    peer_id = _resolve_peer_id("github", login, email, requested_peer_id)
    return ProviderIdentity(provider="github", subject=login, peer_id=peer_id, email=email)


def _verify_okta(access_token: str, requested_peer_id: str) -> ProviderIdentity:
    issuer = os.getenv("ENDE_KEYSERVER_OKTA_ISSUER", "").strip().rstrip("/")
    if not issuer:
        raise ValueError("ENDE_KEYSERVER_OKTA_ISSUER is required for Okta SSO")
    user = _get_json(
        issuer + "/v1/userinfo",
        {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
    )
    subject = str(user.get("preferred_username") or user.get("email") or user.get("sub") or "").strip()
    if not subject:
        raise ValueError("okta token did not return a usable subject")
    email = str(user.get("email", "") or "").strip()
    peer_id = _resolve_peer_id("okta", subject, email, requested_peer_id)
    return ProviderIdentity(provider="okta", subject=subject, peer_id=peer_id, email=email)


def _resolve_peer_id(provider: str, subject: str, email: str, requested_peer_id: str) -> str:
    requested_peer_id = requested_peer_id.strip()
    mapped = _mapped_peer_id(provider, subject, email)
    peer_id = mapped or requested_peer_id or subject.split("@", 1)[0]
    allowed = {v.strip() for v in os.getenv("ENDE_KEYSERVER_ALLOWED_PEERS", "").split(",") if v.strip()}
    if allowed and peer_id not in allowed:
        raise ValueError(f"peer id is not allowed: {peer_id}")
    if requested_peer_id and mapped and requested_peer_id != mapped:
        raise ValueError("requested peer id does not match SSO identity mapping")
    if requested_peer_id and not mapped and requested_peer_id != subject and requested_peer_id != subject.split("@", 1)[0]:
        raise ValueError("requested peer id does not match SSO identity")
    return peer_id


def _mapped_peer_id(provider: str, subject: str, email: str) -> str:
    raw = os.getenv("ENDE_KEYSERVER_IDENTITY_MAP", "")
    keys = {f"{provider}:{subject}", subject}
    if email:
        keys.add(email)
        keys.add(f"{provider}:{email}")
    for item in raw.split(","):
        if "=" not in item:
            continue
        left, right = item.split("=", 1)
        if left.strip() in keys:
            return right.strip()
    return ""


def _get_json(url: str, headers: dict[str, str]) -> dict:
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read()
    data = json.loads(body.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("provider response must be a JSON object")
    return data
