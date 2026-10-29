from __future__ import annotations

import atexit
import base64
import json
import math
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from ipaddress import ip_address
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from uuid import uuid4

from cloud_dast.infrastructure.secrets import secret_value
from cloud_dast.ports import EvidenceChannel, EvidenceEvent

_CALLBACK_METHODS = frozenset({"GET", "POST", "HEAD"})
_OOB_PROTOCOLS = frozenset(
    {"http", "https", "dns", "smtp", "ldap", "ftp", "smb", "responder"}
)
_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
_ZBASE32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769"
_MAX_MARKER_LENGTH = 256
_MAX_PATH_LENGTH = 2048
_MAX_CALLBACK_BODY_BYTES = 4096
_INTERACTSH_CORRELATION_LENGTH = 20
_INTERACTSH_NONCE_LENGTH = 13
_INTERACTSH_MAX_RESPONSE_BYTES = 1_048_576
_INTERACTSH_MAX_INTERACTIONS = 256
_INTERACTSH_POLL_ERROR_LIMIT = 3


class _NoRedirectHandler(HTTPRedirectHandler):
    """Prevent an Interactsh endpoint from forwarding the auth token."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Any:
        raise HTTPError(
            newurl,
            code,
            "Interactsh redirects are forbidden",
            headers,
            fp,
        )


_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler)


def _open_without_redirects(request: Request, timeout: float) -> Any:
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


class _CallbackRateLimiter:
    """Bound local callback processing with a global sliding-window limiter."""

    def __init__(self, *, capacity: int = 100, window: float = 10.0) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        if window <= 0 or not math.isfinite(window):
            raise ValueError("window must be a finite positive number")
        self._capacity = capacity
        self._window = window
        self._lock = threading.Lock()
        self._timestamps: deque[float] = deque()

    def allow(self, now: float) -> bool:
        with self._lock:
            threshold = now - self._window
            while self._timestamps and self._timestamps[0] <= threshold:
                self._timestamps.popleft()
            if len(self._timestamps) >= self._capacity:
                return False
            self._timestamps.append(now)
            return True


class InteractshTransport(Protocol):
    """Runtime port implemented by the REST registration/polling adapter."""

    @property
    def callback_host(self) -> str: ...

    def start(self) -> Any: ...

    def poll(self, session: Any) -> tuple[dict[str, Any], ...]: ...

    def stop(self, session: Any) -> None: ...


@dataclass(frozen=True, slots=True)
class _InteractshSession:
    correlation_id: str
    secret_key: str
    private_key: Any


class InteractshClient:
    """Thin HTTPS client for the Interactsh registration/polling protocol."""

    def __init__(
        self,
        server_url: str,
        token: str,
        *,
        timeout: float = 5.0,
        max_response_bytes: int = _INTERACTSH_MAX_RESPONSE_BYTES,
        max_interactions: int = _INTERACTSH_MAX_INTERACTIONS,
        urlopen_: Callable[..., Any] = _open_without_redirects,
    ) -> None:
        if not token:
            raise ValueError("Interactsh token must not be empty")
        if timeout <= 0 or not math.isfinite(timeout):
            raise ValueError("timeout must be a finite positive number")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        if max_interactions <= 0:
            raise ValueError("max_interactions must be positive")
        parsed = urlsplit(server_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Interactsh server URL must be an HTTPS origin")
        try:
            ip_address(parsed.hostname or "")
        except ValueError:
            pass
        else:
            raise ValueError("Interactsh server URL must use a DNS hostname")
        self._server_url = server_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._max_response_bytes = max_response_bytes
        self._max_interactions = max_interactions
        self._urlopen = urlopen_
        self.callback_host = parsed.netloc

    def start(self) -> _InteractshSession:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        correlation_id = _random_id(_XID_ALPHABET, _INTERACTSH_CORRELATION_LENGTH)
        secret_key = str(uuid4())
        response = self._request_json(
            "POST",
            "register",
            {
                "public-key": base64.b64encode(public_key).decode("ascii"),
                "secret-key": secret_key,
                "correlation-id": correlation_id,
            },
        )
        if response.get("message") != "registration successful":
            raise RuntimeError("Interactsh registration was not accepted")
        return _InteractshSession(
            correlation_id=correlation_id,
            secret_key=secret_key,
            private_key=private_key,
        )

    def poll(self, session: _InteractshSession) -> tuple[dict[str, Any], ...]:
        query = urlencode({"id": session.correlation_id, "secret": session.secret_key})
        payload = self._request_json("GET", f"poll?{query}", None)
        encrypted = self._strings(payload, "data")
        extra = self._strings(payload, "extra")
        tld_data = self._strings(payload, "tlddata")
        if len(encrypted) + len(extra) + len(tld_data) > self._max_interactions:
            raise ValueError("Interactsh poll returned too many interactions")

        interactions: list[dict[str, Any]] = []
        if encrypted:
            aes_key = self._decrypt_key(payload.get("aes_key"), session.private_key)
            interactions.extend(
                self._decrypt_interaction(value, aes_key) for value in encrypted
            )
        interactions.extend(self._decode_interaction(value) for value in extra)
        interactions.extend(self._decode_interaction(value) for value in tld_data)
        return tuple(interactions)

    def stop(self, session: _InteractshSession) -> None:
        self._request_json(
            "POST",
            "deregister",
            {
                "correlation-id": session.correlation_id,
                "secret-key": session.secret_key,
            },
        )

    def _request_json(
        self,
        method: str,
        path: str,
        payload: dict[str, object] | None,
    ) -> dict[str, Any]:
        data = (
            None
            if payload is None
            else json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        headers["Authorization"] = self._token
        url = urljoin(f"{self._server_url}/", path)
        request = Request(url, data=data, headers=headers, method=method)
        try:
            response = self._urlopen(request, timeout=self._timeout)
        except HTTPError as error:
            raise RuntimeError(
                f"Interactsh {path.split('?', 1)[0]} request failed "
                f"with HTTP {error.code}"
            ) from error
        except URLError as error:
            raise RuntimeError(
                f"Interactsh {path.split('?', 1)[0]} request failed"
            ) from error
        try:
            body = self._read_body(response)
        except ValueError:
            self._close(response)
            raise
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise ValueError("Interactsh returned an invalid JSON response") from None
        finally:
            self._close(response)
        if not isinstance(decoded, dict):
            raise ValueError("Interactsh response must be a JSON object")
        return decoded

    def _read_body(self, response: Any) -> bytes:
        headers = getattr(response, "headers", None)
        content_length = headers.get("Content-Length") if headers is not None else None
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                raise ValueError("invalid Interactsh Content-Length") from None
            if length < 0 or length > self._max_response_bytes:
                raise ValueError("Interactsh response exceeds the byte cap")
        body = response.read(self._max_response_bytes + 1)
        if not isinstance(body, bytes):
            raise ValueError("Interactsh response body must be bytes")
        if len(body) > self._max_response_bytes:
            raise ValueError("Interactsh response exceeds the byte cap")
        return body

    @staticmethod
    def _close(response: Any) -> None:
        close = getattr(response, "close", None)
        if callable(close):
            close()

    def _strings(self, payload: dict[str, Any], name: str) -> tuple[str, ...]:
        value = payload.get(name, [])
        if not isinstance(value, list) or any(
            not isinstance(item, str) for item in value
        ):
            raise ValueError(f"Interactsh {name} must be an array of strings")
        return tuple(value)

    def _decrypt_key(self, value: object, private_key: Any) -> bytes:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        if not isinstance(value, str):
            raise ValueError("Interactsh encrypted AES key must be a string")
        try:
            encrypted_key = base64.b64decode(value, validate=True)
            key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except (ValueError, TypeError) as error:
            raise ValueError("invalid Interactsh encrypted AES key") from error
        if len(key) not in {16, 24, 32}:
            raise ValueError("invalid Interactsh AES key length")
        return key

    def _decrypt_interaction(self, value: str, key: bytes) -> dict[str, Any]:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        try:
            ciphertext = base64.b64decode(value, validate=True)
        except (ValueError, TypeError) as error:
            raise ValueError("invalid Interactsh encrypted interaction") from error
        if len(ciphertext) < 16:
            raise ValueError("Interactsh encrypted interaction is too short")
        decryptor = Cipher(
            algorithms.AES(key),
            modes.CTR(ciphertext[:16]),
        ).decryptor()
        plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
        return self._decode_interaction(plaintext.decode("utf-8"))

    @staticmethod
    def _decode_interaction(value: str) -> dict[str, Any]:
        try:
            interaction = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
            raise ValueError("invalid Interactsh interaction JSON") from error
        if not isinstance(interaction, dict):
            raise ValueError("Interactsh interaction must be a JSON object")
        return interaction


class OobCollaborator:
    """Build OOB URLs through Interactsh, with a loopback listener fallback."""

    def __init__(
        self,
        events: EvidenceChannel,
        *,
        host: str | None = None,
        port: int | None = None,
        client: InteractshTransport | None = None,
        server_url: str | None = None,
        token: str | None = None,
        clock: Callable[[], float] = time.time,
        poll_interval: float | None = None,
        expected_capacity: int = 10_000,
    ) -> None:
        self._events = events
        self._clock = clock
        if expected_capacity <= 0:
            reason = "expected_capacity must be positive"
            events.block(reason)
            raise RuntimeError(reason)
        self._expected_capacity = expected_capacity
        self._lock = threading.Lock()
        self._expected_payloads: OrderedDict[str, str] = OrderedDict()
        self._markers_by_payload: dict[str, str] = {}
        self._atexit_registered = False
        self._rate_limiter = _CallbackRateLimiter()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._poll_lock = threading.Lock()

        if client is not None and (server_url is not None or token is not None):
            reason = "an injected Interactsh client cannot be combined with URL config"
            events.block(reason)
            raise RuntimeError(reason)

        self._external_client = client
        if self._external_client is None:
            selected_server_url = (
                server_url
                if server_url is not None
                else os.environ.get("CLOUD_DAST_OOB_SERVER_URL", "").strip()
            )
            if selected_server_url:
                try:
                    selected_token = (
                        token
                        if token is not None
                        else secret_value("CLOUD_DAST_OOB_TOKEN")
                    )
                except (OSError, UnicodeDecodeError) as error:
                    reason = "invalid Interactsh OOB token configuration"
                    events.block(reason)
                    raise RuntimeError(reason) from error
                try:
                    self._external_client = InteractshClient(
                        selected_server_url,
                        selected_token,
                    )
                except (TypeError, ValueError) as error:
                    reason = "invalid Interactsh OOB configuration"
                    events.block(reason)
                    raise RuntimeError(reason) from error

        self._session: Any | None = None
        self._poll_thread: threading.Thread | None = None
        self._poll_stop: threading.Event | None = None
        if self._external_client is not None:
            self._host = None
            self._port = None
            if poll_interval is None:
                environment_interval = os.environ.get(
                    "CLOUD_DAST_OOB_POLL_INTERVAL",
                    "",
                ).strip()
                try:
                    poll_interval = (
                        float(environment_interval) if environment_interval else 0.5
                    )
                except ValueError as error:
                    reason = "CLOUD_DAST_OOB_POLL_INTERVAL must be a number"
                    events.block(reason)
                    raise RuntimeError(reason) from error
            if poll_interval <= 0 or not math.isfinite(poll_interval):
                reason = "poll_interval must be a finite positive number"
                events.block(reason)
                raise RuntimeError(reason)
            self._poll_interval = poll_interval
            return

        environment_host = os.environ.get("CLOUD_DAST_OOB_HOST", "").strip()
        environment_port = os.environ.get("CLOUD_DAST_OOB_PORT", "").strip()
        try:
            environment_port_value = int(environment_port or "0")
        except ValueError as error:
            reason = "CLOUD_DAST_OOB_PORT must be an integer"
            events.block(reason)
            raise RuntimeError(reason) from error
        self._host = host or environment_host or "127.0.0.1"
        self._port = port if port is not None else environment_port_value
        if not self._is_loopback_host(self._host):
            reason = "local OOB fallback listener must bind to loopback"
            events.block(reason)
            raise RuntimeError(reason)
        if not 0 <= self._port <= 65_535:
            reason = "local OOB fallback port must be between 0 and 65535"
            events.block(reason)
            raise RuntimeError(reason)

    def url_for(self, marker: str) -> str:
        self.start()
        try:
            payload = self._payload_for(marker)
        except (RuntimeError, ValueError) as error:
            reason = str(error)
            self._events.block(reason)
            raise RuntimeError(reason) from error
        if self._external_client is not None:
            return f"https://{payload}.{self._external_client.callback_host}"
        with self._lock:
            server = self._server
        if server is None:  # pragma: no cover - start always creates a server
            raise RuntimeError("out-of-band listener is not running")
        return f"{self._listener_url(server)}/{quote(marker, safe='')}"

    def start(self) -> None:
        if self._external_client is None:
            self._start_listener()
            self._events.set_ready(True)
            return
        with self._lock:
            if self._session is not None:
                return
            try:
                session = self._external_client.start()
            except Exception as error:
                reason = "Interactsh registration failed"
                self._events.block(reason)
                raise RuntimeError(reason) from error
            stop_event = threading.Event()
            thread = threading.Thread(
                target=self._poll_loop,
                args=(stop_event,),
                name="cloud-dast-oob-poller",
                daemon=True,
            )
            self._session = session
            self._poll_stop = stop_event
            self._poll_thread = thread
        thread.start()
        self._events.set_ready(True)

    def poll_once(self) -> None:
        """Poll one batch and record only expected marker interactions."""

        with self._poll_lock:
            with self._lock:
                session = self._session
            if session is None or self._external_client is None:
                raise RuntimeError("Interactsh OOB channel is not started")
            self._poll_interactions(session)

    def stop(self) -> None:
        if self._external_client is not None:
            self._stop_external()
            return
        with self._lock:
            server = self._server
            self._server = None
            self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        self._events.block("out-of-band listener stopped")
        self._unregister_atexit()

    def _poll_loop(self, stop_event: threading.Event) -> None:
        errors = 0
        while not stop_event.wait(self._poll_interval):
            try:
                self.poll_once()
            except Exception:
                errors += 1
                if errors >= _INTERACTSH_POLL_ERROR_LIMIT:
                    self._events.block(
                        "Interactsh polling failed after consecutive attempts"
                    )
                    return
            else:
                errors = 0

    def _stop_external(self) -> None:
        with self._lock:
            session = self._session
            thread = self._poll_thread
            stop_event = self._poll_stop
            self._session = None
            self._poll_thread = None
            self._poll_stop = None
        if stop_event is not None:
            stop_event.set()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(1.0, self._poll_interval * 2))
            if thread.is_alive():
                self._events.block("Interactsh OOB poller did not stop")
                return
        final_poll_failed = False
        if session is not None and self._external_client is not None:
            try:
                with self._poll_lock:
                    self._poll_interactions(session)
            except Exception:
                final_poll_failed = True
        reason = "out-of-band channel stopped"
        if session is not None and self._external_client is not None:
            try:
                with self._poll_lock:
                    self._external_client.stop(session)
            except Exception:
                reason = "Interactsh deregistration failed"
        if final_poll_failed:
            reason = "Interactsh final poll failed"
        self._events.block(reason)
        self._unregister_atexit()

    def _poll_interactions(self, session: Any) -> None:
        if self._external_client is None:
            raise RuntimeError("Interactsh OOB channel is not started")
        interactions = self._external_client.poll(session)
        for interaction in interactions:
            marker = self._marker_for_interaction(interaction)
            if marker is None:
                continue
            self._events.record(_event_from_interactsh(interaction, marker))

    def _payload_for(self, marker: str) -> str:
        _validate_marker(marker)
        with self._lock:
            payload = self._expected_payloads.get(marker)
            if payload is not None:
                return payload
            if len(self._expected_payloads) >= self._expected_capacity:
                oldest, oldest_payload = self._expected_payloads.popitem(last=False)
                del self._markers_by_payload[oldest_payload]
            if self._external_client is None:
                payload = marker
            else:
                session = self._session
                if session is None:
                    raise RuntimeError("Interactsh OOB channel is not started")
                payload = session.correlation_id + _random_id(
                    _ZBASE32_ALPHABET,
                    _INTERACTSH_NONCE_LENGTH,
                )
            self._expected_payloads[marker] = payload
            self._markers_by_payload[payload] = marker
            return payload

    def _marker_for_interaction(self, interaction: dict[str, Any]) -> str | None:
        with self._lock:
            for name in ("unique-id", "full-id"):
                value = interaction.get(name)
                if not isinstance(value, str) or not value:
                    continue
                label = value.split(".", 1)[0].lower()
                marker = self._markers_by_payload.get(label)
                if marker is not None:
                    return marker
        return None

    def _accept_marker(self, marker: str) -> bool:
        with self._lock:
            return marker in self._expected_payloads

    def _start_listener(self) -> str:
        with self._lock:
            if self._server is not None:
                return self._listener_url(self._server)
            events = self._events
            clock = self._clock
            collaborator = self

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:
                    self._record()

                def do_POST(self) -> None:
                    self._record()

                def do_HEAD(self) -> None:
                    self._record()

                def _record(self) -> None:
                    if len(self.path) > _MAX_PATH_LENGTH:
                        self.send_response(414)
                        self.end_headers()
                        return
                    try:
                        content_length = int(
                            self.headers.get("Content-Length", "0") or "0"
                        )
                    except ValueError:
                        content_length = _MAX_CALLBACK_BODY_BYTES + 1
                    if content_length < 0:
                        self.send_response(400)
                        self.end_headers()
                        return
                    if content_length > _MAX_CALLBACK_BODY_BYTES:
                        self.send_response(413)
                        self.end_headers()
                        return
                    if content_length:
                        self.rfile.read(content_length)

                    parsed = urlsplit(self.path)
                    query_marker = parse_qs(parsed.query).get("marker", [""])
                    segments = tuple(
                        segment for segment in parsed.path.split("/") if segment
                    )
                    raw_marker = query_marker[0] or (segments[-1] if segments else "")
                    marker = unquote(raw_marker)
                    if not collaborator._accept_marker(marker):
                        self.send_response(404)
                        self.end_headers()
                        return
                    if not collaborator._rate_limiter.allow(clock()):
                        self.send_response(429)
                        self.end_headers()
                        return
                    try:
                        events.record(
                            EvidenceEvent(
                                correlation_id=marker,
                                channel="oob",
                                event_type="http",
                                source=self.client_address[0],
                                observed_at=clock(),
                                attributes=(
                                    ("method", self.command),
                                    ("path", self.path),
                                ),
                            )
                        )
                    except ValueError:
                        self.send_response(400)
                    else:
                        self.send_response(204)
                    self.end_headers()

                def log_message(self, format: str, *args: Any) -> None:
                    del format, args

            try:
                server = HTTPServer((self._host, self._port), Handler)
            except OSError as error:
                reason = (
                    f"cannot bind out-of-band listener on "
                    f"{self._host}:{self._port}: {error}"
                )
                events.block(reason)
                raise RuntimeError(reason) from error
            thread = threading.Thread(
                target=server.serve_forever,
                name="cloud-dast-oob-listener",
                daemon=True,
            )
            thread.start()
            self._server = server
            self._thread = thread

        if not self._atexit_registered:
            atexit.register(self.stop)
            self._atexit_registered = True
        return self._listener_url(server)

    def _listener_url(self, server: HTTPServer) -> str:
        host, port = server.server_address[:2]
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{port}"

    def _unregister_atexit(self) -> None:
        if self._atexit_registered:
            atexit.unregister(self.stop)
            self._atexit_registered = False

    @staticmethod
    def _is_loopback_host(host: str) -> bool:
        if host == "localhost":
            return True
        try:
            return ip_address(host).is_loopback
        except ValueError:
            return False


def _event_from_interactsh(
    interaction: dict[str, Any],
    marker: str,
) -> EvidenceEvent:
    protocol_value = interaction.get("protocol")
    if not isinstance(protocol_value, str):
        raise ValueError("Interactsh interaction protocol must be a string")
    protocol = protocol_value.lower()
    _validate_protocol(protocol)
    unique_id = interaction.get("unique-id")
    full_id = interaction.get("full-id")
    if not isinstance(unique_id, str) and not isinstance(full_id, str):
        raise ValueError("Interactsh interaction has no callback identifier")
    if protocol in {"http", "https"}:
        raw_request = interaction.get("raw-request", "")
        request_line = (
            raw_request.splitlines()[0] if isinstance(raw_request, str) else ""
        )
        request_parts = request_line.split()
        method = (
            request_parts[0].upper()
            if request_parts and request_parts[0].upper() in _CALLBACK_METHODS
            else "GET"
        )
        path = (
            request_parts[1]
            if len(request_parts) > 1
            else (full_id if isinstance(full_id, str) else unique_id)
        )
    else:
        method = protocol.upper()
        path = full_id if isinstance(full_id, str) else unique_id
    remote_address = interaction.get("remote-address")
    if not isinstance(remote_address, str):
        raise ValueError("Interactsh interaction remote-address must be a string")
    timestamp = interaction.get("timestamp")
    if not isinstance(timestamp, str):
        raise ValueError("Interactsh interaction timestamp must be a string")
    return EvidenceEvent(
        correlation_id=marker,
        channel="oob",
        event_type=protocol,
        source=_source_ip_from_interactsh(remote_address),
        observed_at=_timestamp_from_interactsh(timestamp),
        attributes=(
            ("method", method),
            ("path", path),
        ),
    )


def _source_ip_from_interactsh(remote_address: str) -> str:
    if not remote_address:
        return ""
    if remote_address.startswith("["):
        source_ip = remote_address[1:].split("]", 1)[0]
    elif remote_address.count(":") == 1:
        source_ip = remote_address.rsplit(":", 1)[0]
    else:
        source_ip = remote_address
    try:
        ip_address(source_ip)
    except ValueError as error:
        raise ValueError("Interactsh interaction has an invalid source IP") from error
    return source_ip


def _timestamp_from_interactsh(timestamp: str) -> float:
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        value = parsed.timestamp()
    except ValueError as error:
        raise ValueError("Interactsh interaction has an invalid timestamp") from error
    if not math.isfinite(value) or value < 0:
        raise ValueError("Interactsh interaction has an invalid timestamp")
    return value


def _validate_protocol(protocol: str) -> None:
    if protocol not in _OOB_PROTOCOLS:
        raise ValueError("OOB event protocol is not supported")


def _validate_marker(marker: str) -> None:
    if not marker:
        raise ValueError("OOB marker must not be empty")
    if len(marker) > _MAX_MARKER_LENGTH or any(ord(char) < 32 for char in marker):
        raise ValueError("OOB marker is invalid")


def _random_id(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))
