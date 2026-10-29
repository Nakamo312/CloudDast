#!/usr/bin/env python3
"""Exchange a Yandex Cloud authorized key for a short-lived IAM token."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_IAM_ENDPOINT = "https://iam.api.cloud.yandex.net/iam/v1/tokens"
TOKEN_TTL_SECONDS = 3600


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-file",
        default=os.environ.get("CLOUD_DAST_IAM_AUTHORIZED_KEY_FILE", ""),
        help="authorized key JSON; defaults to CLOUD_DAST_IAM_AUTHORIZED_KEY_FILE",
    )
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("CLOUD_DAST_IAM_ENDPOINT", DEFAULT_IAM_ENDPOINT),
    )
    args = parser.parse_args()
    if not args.key_file:
        parser.error("an authorized key file is required")
    if not args.endpoint:
        parser.error("IAM endpoint must not be empty")

    try:
        token = fetch_token(Path(args.key_file), args.endpoint)
    except Exception:
        print("IAM token exchange failed", file=sys.stderr)
        return 1
    print(token)
    return 0


def fetch_token(key_path: Path, endpoint: str) -> str:
    key = load_key(key_path)
    jwt = make_jwt(key)
    request = urllib.request.Request(
        endpoint,
        data=json.dumps({"jwt": jwt}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload: dict[str, Any] = json.load(response)
    token = payload.get("iamToken")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("IAM response has no iamToken")
    return token.strip()


def load_key(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise FileNotFoundError(str(path))
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("authorized key must be a JSON object")
    for field in ("service_account_id", "private_key"):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise ValueError(f"authorized key lacks {field}")
    return value


def make_jwt(key: dict[str, str]) -> str:
    now = int(time.time())
    key_id = str(key.get("key_id") or key.get("id") or "")
    header = encode_json({"alg": "PS256", "typ": "JWT", "kid": key_id})
    payload = encode_json(
        {
            "iss": key["service_account_id"],
            "aud": "https://iam.api.cloud.yandex.net/iam/v1/tokens",
            "iat": now,
            "exp": now + TOKEN_TTL_SECONDS,
        }
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = sign_ps256(key["private_key"], signing_input)
    return f"{header}.{payload}.{signature}"


def sign_ps256(private_key: str, signing_input: bytes) -> str:
    key_text = private_key
    begin = key_text.find("-----BEGIN")
    if begin > 0:
        key_text = key_text[begin:]
    digest = hashlib.sha256(signing_input).digest()
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".pem", delete=True
    ) as key_file:
        key_file.write(key_text)
        key_file.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                key_file.name,
                "-pkeyopt",
                "digest:sha256",
                "-pkeyopt",
                "rsa_padding_mode:pss",
                "-pkeyopt",
                "rsa_pss_saltlen:32",
            ],
            input=digest,
            capture_output=True,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError("openssl signing failed")
    return base64.urlsafe_b64encode(result.stdout).rstrip(b"=").decode("ascii")


def encode_json(value: dict[str, Any]) -> str:
    raw = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


if __name__ == "__main__":
    raise SystemExit(main())
