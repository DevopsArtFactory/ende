from __future__ import annotations

import json
import os
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .models import PeerProfile, TokenRecord


class Store(ABC):
    @abstractmethod
    def get(self, peer_id: str) -> PeerProfile | None:
        raise NotImplementedError

    @abstractmethod
    def put(self, profile: PeerProfile) -> None:
        raise NotImplementedError

    @abstractmethod
    def delete(self, peer_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def get_token(self, token_hash: str) -> TokenRecord | None:
        raise NotImplementedError

    @abstractmethod
    def put_token(self, token: TokenRecord) -> None:
        raise NotImplementedError


class MemoryStore(Store):
    def __init__(self) -> None:
        self._profiles: dict[str, PeerProfile] = {}
        self._tokens: dict[str, TokenRecord] = {}

    def get(self, peer_id: str) -> PeerProfile | None:
        return self._profiles.get(peer_id)

    def put(self, profile: PeerProfile) -> None:
        self._profiles[profile.id] = profile

    def delete(self, peer_id: str) -> bool:
        return self._profiles.pop(peer_id, None) is not None

    def get_token(self, token_hash: str) -> TokenRecord | None:
        return self._tokens.get(token_hash)

    def put_token(self, token: TokenRecord) -> None:
        self._tokens[token.token_hash] = token


class FileStore(Store):
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def get(self, peer_id: str) -> PeerProfile | None:
        raw = self._read_root()["profiles"].get(peer_id)
        if raw is None:
            return None
        return PeerProfile.from_dict(raw, expected_id=peer_id)

    def put(self, profile: PeerProfile) -> None:
        root = self._read_root()
        root["profiles"][profile.id] = profile.to_dict()
        self._write_root(root)

    def delete(self, peer_id: str) -> bool:
        root = self._read_root()
        if peer_id not in root["profiles"]:
            return False
        del root["profiles"][peer_id]
        self._write_root(root)
        return True

    def get_token(self, token_hash: str) -> TokenRecord | None:
        raw = self._read_root()["tokens"].get(token_hash)
        if raw is None:
            return None
        return TokenRecord.from_dict(raw)

    def put_token(self, token: TokenRecord) -> None:
        root = self._read_root()
        root["tokens"][token.token_hash] = token.to_dict()
        self._write_root(root)

    def _read_root(self) -> dict[str, dict[str, dict[str, str]]]:
        if not self.path.exists():
            return {"profiles": {}, "tokens": {}}
        with self.path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("file store root must be an object")
        if "profiles" in data or "tokens" in data:
            profiles = data.get("profiles", {})
            tokens = data.get("tokens", {})
            if not isinstance(profiles, dict) or not isinstance(tokens, dict):
                raise ValueError("file store profiles/tokens must be objects")
            return {"profiles": profiles, "tokens": tokens}
        return {"profiles": data, "tokens": {}}

    def _write_root(self, data: dict[str, dict[str, dict[str, str]]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=str(self.path.parent))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.write("\n")
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)


class DynamoDBStore(Store):
    def __init__(self, table_name: str, region_name: str | None = None) -> None:
        try:
            import boto3
        except ImportError as exc:
            raise RuntimeError("boto3 is required for ENDE_KEYSERVER_BACKEND=dynamodb") from exc
        self._table = boto3.resource("dynamodb", region_name=region_name).Table(table_name)

    def get(self, peer_id: str) -> PeerProfile | None:
        item = self._table.get_item(Key={"id": peer_id}).get("Item")
        if item is None:
            return None
        return PeerProfile.from_dict(dict(item), expected_id=peer_id)

    def put(self, profile: PeerProfile) -> None:
        self._table.put_item(Item=profile.to_dict())

    def delete(self, peer_id: str) -> bool:
        result = self._table.delete_item(Key={"id": peer_id}, ReturnValues="ALL_OLD")
        return "Attributes" in result

    def get_token(self, token_hash: str) -> TokenRecord | None:
        item = self._table.get_item(Key={"id": f"token#{token_hash}"}).get("Item")
        if item is None:
            return None
        return TokenRecord.from_dict(dict(item))

    def put_token(self, token: TokenRecord) -> None:
        item = token.to_dict()
        item["id"] = f"token#{token.token_hash}"
        item["kind"] = "token"
        self._table.put_item(Item=item)


def store_from_env() -> Store:
    backend = os.getenv("ENDE_KEYSERVER_BACKEND", "file").strip().lower()
    if backend == "memory":
        return MemoryStore()
    if backend == "file":
        return FileStore(os.getenv("ENDE_KEYSERVER_FILE", ".ende-keyserver.json"))
    if backend == "dynamodb":
        table = os.getenv("ENDE_KEYSERVER_DDB_TABLE", "").strip()
        if not table:
            raise ValueError("ENDE_KEYSERVER_DDB_TABLE is required for DynamoDB backend")
        return DynamoDBStore(table, os.getenv("ENDE_KEYSERVER_AWS_REGION") or None)
    raise ValueError(f"unsupported keyserver backend: {backend}")
