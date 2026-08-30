#!/usr/bin/env python3
"""common.py — shared helpers for all scanners (logging, shell, HTTP, findings)."""

from __future__ import annotations

import shutil
import subprocess
import sys

import knowledgebase as kb

# Optional requests
try:
    import requests  # type: ignore

    HAS_REQUESTS = True
except Exception:  # pragma: no cover
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error


class C:
    _on = sys.stdout.isatty()
    RESET = "\033[0m" if _on else ""
    BOLD = "\033[1m" if _on else ""
    RED = "\033[31m" if _on else ""
    GRN = "\033[32m" if _on else ""
    YEL = "\033[33m" if _on else ""
    BLU = "\033[34m" if _on else ""
    CYN = "\033[36m" if _on else ""
    MAG = "\033[35m" if _on else ""


def banner(text: str) -> None:
    print(f"\n{C.CYN}{'=' * 72}\n== {text}\n{'=' * 72}{C.RESET}")


def info(m: str) -> None:
    print(f"{C.BLU}[*]{C.RESET} {m}")


def ok(m: str) -> None:
    print(f"{C.GRN}[+]{C.RESET} {m}")


def warn(m: str) -> None:
    print(f"{C.YEL}[!]{C.RESET} {m}")


def err(m: str) -> None:
    print(f"{C.RED}[x]{C.RESET} {m}")


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    """Run a command, capture combined output, never raise."""
    info("running: " + " ".join(cmd))
    try:
        p = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout
        )
        return p.returncode, p.stdout
    except subprocess.TimeoutExpired as e:
        out = e.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return 124, f"[timeout after {timeout}s]\n{out}"
    except FileNotFoundError:
        return 127, f"[tool not found: {cmd[0]}]"
    except Exception as e:  # pragma: no cover
        return 1, f"[error running {cmd[0]}: {e}]"


def run_live(cmd: list[str], timeout: int = 900) -> int:
    """
    Run a command with its output streamed straight to the terminal (so the user
    sees live progress). Returns the exit code. On timeout, returns 124.
    Use for long tools like nmap; pair with the tool's own -oN/-o file to persist
    output for the report.
    """
    info("running: " + " ".join(cmd) + f"   (timeout {timeout}s — Ctrl+C to skip)")
    try:
        return subprocess.run(cmd, timeout=timeout).returncode
    except subprocess.TimeoutExpired:
        warn(f"'{cmd[0]}' hit the {timeout}s time limit — moving on with partial results")
        return 124
    except FileNotFoundError:
        return 127
    except KeyboardInterrupt:
        warn(f"'{cmd[0]}' skipped by user (Ctrl+C)")
        return 130
    except Exception as e:  # pragma: no cover
        warn(f"error running {cmd[0]}: {e}")
        return 1


def http_get(url: str, timeout: int = 15):
    """Return (status, headers_lowercased, body_text, cookiejar_or_None)."""
    headers = {"User-Agent": "vulnscan/2.0 (+authorized-testing)"}
    if HAS_REQUESTS:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.text, r.cookies
    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read().decode("utf-8", "replace"), None
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read().decode("utf-8", "replace"), None


def finding(fid: str, evidence: str, severity_override: str | None = None) -> dict:
    """
    Build an enriched finding from a KB id + evidence string.
    The reporter uses these fields directly.
    """
    e = kb.get(fid)
    return {
        "id": fid,
        "severity": severity_override or e["severity"],
        "title": e["title"],
        "cwe": e["cwe"],
        "owasp": e["owasp"],
        "description": e["description"],
        "attack": e["attack"],
        "patch": e["patch"],
        "evidence": evidence,
    }
