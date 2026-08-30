#!/usr/bin/env python3
"""
validation/oast.py — controlled out-of-band (OAST) collaborator for SAFE proof
of blind vulnerability classes (spec §37/§38: SSRF, blind XXE, blind RCE, etc.).

The idea: instead of "weaponizing" a target, we ask it to make a request to a
collaborator WE control, tagged with a unique benign token. If the collaborator
observes the callback, the vulnerability is PROVEN with evidence — non-destructively.

Safety model:
  * off by default — a validator only uses a collaborator that is explicitly provided
  * benign unique markers only; no payloads that damage the target
  * bounded (single request), timed-out, and abortable
  * if no collaborator is configured, blind classes return MANUAL_VALIDATION_REQUIRED,
    never a fabricated "validated"

Two collaborators are provided:
  * LocalCollaborator — an in-process HTTP listener for AUTHORIZED LABS / tests
  * ExternalCollaborator — a boundary/adapter for a real OAST service (e.g. an
    interactsh-style domain) supplied by the operator; marked as requiring config.
"""

from __future__ import annotations

import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer


class LocalCollaborator:
    """In-process HTTP collaborator for authorized-lab proof. Records callbacks by token."""

    def __init__(self):
        self._hits: dict[str, list] = {}
        self._srv = None
        self._base = ""

    def start(self) -> "LocalCollaborator":
        hits = self._hits

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                # the token is embedded in the path: /oast/<token>
                tok = self.path.rstrip("/").split("/")[-1].split("?")[0]
                hits.setdefault(tok, []).append({"path": self.path,
                                                 "ua": self.headers.get("User-Agent", ""),
                                                 "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, *a):  # silence
                pass

        self._srv = HTTPServer(("127.0.0.1", 0), _H)
        self._base = f"http://127.0.0.1:{self._srv.server_address[1]}"
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        return self

    def stop(self) -> None:
        if self._srv:
            self._srv.shutdown()
            self._srv = None

    def new_token(self) -> str:
        return "oast" + uuid.uuid4().hex[:16]

    def callback_url(self, token: str) -> str:
        return f"{self._base}/oast/{token}"

    def received(self, token: str, wait: float = 2.0) -> bool:
        deadline = time.time() + wait
        while time.time() < deadline:
            if self._hits.get(token):
                return True
            time.sleep(0.05)
        return bool(self._hits.get(token))

    def evidence(self, token: str) -> dict:
        return {"callbacks": self._hits.get(token, [])}


class ExternalCollaborator:
    """
    Adapter boundary for a REAL OAST service (operator-supplied, e.g. interactsh).
    Not wired to a live service here (that requires operator configuration/network);
    exposing the interface keeps the architecture complete and honest.
    """

    def __init__(self, base_url: str, poll):
        self.base_url = base_url.rstrip("/")
        self._poll = poll  # callable(token) -> bool, provided by the operator adapter

    def new_token(self) -> str:
        return "oast" + uuid.uuid4().hex[:16]

    def callback_url(self, token: str) -> str:
        return f"{self.base_url}/{token}"

    def received(self, token: str, wait: float = 5.0) -> bool:
        return bool(self._poll and self._poll(token))

    def evidence(self, token: str) -> dict:
        return {"collaborator": self.base_url, "token": token}


def prove_ssrf(target_url: str, param: str, collaborator, timeout: int = 8) -> tuple:
    """
    SAFE SSRF proof: inject the collaborator callback URL into `param` on
    `target_url` (single, bounded request) and check whether the target's
    server-side fetch reached our collaborator. Returns a (state, detail, evidence)
    tuple. Non-destructive: only a benign GET pointing at our own listener.
    """
    import urllib.request
    from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
    if collaborator is None:
        return ("manual", "no OAST collaborator configured (blind SSRF needs one)", {})
    token = collaborator.new_token()
    cb = collaborator.callback_url(token)
    parsed = urlparse(target_url)
    q = parse_qs(parsed.query)
    q[param] = [cb]
    new = parsed._replace(query=urlencode({k: v[-1] for k, v in q.items()}))
    probe = urlunparse(new)
    try:
        req = urllib.request.Request(probe, headers={"User-Agent": "overwatch-oast/1.0"})
        urllib.request.urlopen(req, timeout=timeout).read(64)
    except Exception:
        pass  # the target's own outbound call is what matters, not our response
    if collaborator.received(token, wait=min(timeout, 5)):
        return ("validated", f"server-side request to attacker-controlled collaborator confirmed via '{param}'",
                collaborator.evidence(token))
    return ("not_validated", "no out-of-band callback observed (may still be blind/filtered)", {})
