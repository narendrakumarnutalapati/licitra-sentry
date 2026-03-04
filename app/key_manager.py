"""
LICITRA-SENTRY v0.2 — Key Management

Manages Ed25519 signing keys for execution ticket issuance and verification.
Provides file-based implementation with abstract interface for KMS integration.

Author: Narendra Kumar Nutalapati
License: MIT
"""

import os
import uuid
import json
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


class KeyProvider(ABC):
    """Abstract interface for key providers (file, HSM, KMS)."""

    @abstractmethod
    def get_private_key(self, kid: str) -> Ed25519PrivateKey:
        """Retrieve private signing key by key ID."""
        ...

    @abstractmethod
    def get_public_key(self, kid: str) -> Ed25519PublicKey:
        """Retrieve public verification key by key ID."""
        ...

    @abstractmethod
    def get_active_kid(self) -> str:
        """Return the currently active key ID for signing."""
        ...


class FileKeyProvider(KeyProvider):
    """
    File-based key provider for development and reference deployments.

    Keys are stored as PEM files in a designated directory.
    Key metadata is tracked in a JSON manifest.
    """

    def __init__(self, keys_dir: str = "keys"):
        self.keys_dir = Path(keys_dir)
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_path = self.keys_dir / "manifest.json"
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> dict:
        if self.manifest_path.exists():
            with open(self.manifest_path, "r") as f:
                return json.load(f)
        return {"keys": {}, "active_kid": None}

    def _save_manifest(self):
        with open(self.manifest_path, "w") as f:
            json.dump(self._manifest, f, indent=2)

    def generate_key_pair(self, label: str = "sentry") -> str:
        """
        Generate a new Ed25519 key pair.

        Returns:
            kid: The key identifier for the new key pair.
        """
        kid = f"{label}-{uuid.uuid4().hex[:12]}"
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Write to files
        private_path = self.keys_dir / f"{kid}_private.pem"
        public_path = self.keys_dir / f"{kid}_public.pem"

        with open(private_path, "wb") as f:
            f.write(private_pem)
        os.chmod(private_path, 0o600)

        with open(public_path, "wb") as f:
            f.write(public_pem)

        # Update manifest
        self._manifest["keys"][kid] = {
            "label": label,
            "created": datetime.now(timezone.utc).isoformat(),
            "private_path": str(private_path),
            "public_path": str(public_path),
            "fingerprint": hashlib.sha256(public_pem).hexdigest()[:16],
        }
        self._manifest["active_kid"] = kid
        self._save_manifest()

        return kid

    def get_private_key(self, kid: str) -> Ed25519PrivateKey:
        if kid not in self._manifest["keys"]:
            raise KeyError(f"Key ID not found: {kid}")
        path = Path(self._manifest["keys"][kid]["private_path"])
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def get_public_key(self, kid: str) -> Ed25519PublicKey:
        if kid not in self._manifest["keys"]:
            raise KeyError(f"Key ID not found: {kid}")
        path = Path(self._manifest["keys"][kid]["public_path"])
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    def get_active_kid(self) -> str:
        kid = self._manifest.get("active_kid")
        if kid is None:
            raise RuntimeError("No active signing key. Run generate_key_pair() first.")
        return kid

    def get_public_key_pem(self, kid: str) -> bytes:
        """Return raw PEM bytes for the public key (for distribution)."""
        if kid not in self._manifest["keys"]:
            raise KeyError(f"Key ID not found: {kid}")
        path = Path(self._manifest["keys"][kid]["public_path"])
        with open(path, "rb") as f:
            return f.read()
