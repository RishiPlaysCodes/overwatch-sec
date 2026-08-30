#!/usr/bin/env python3
"""
reporting/pdf.py — PDF report generation.

Strategy (best available, always produces a file):
  1. If wkhtmltopdf or weasyprint is installed, render the rich HTML report.
  2. Otherwise, emit a clean, paginated text PDF via a tiny built-in writer
     (dependency-free) from the assessment summary + findings.

The built-in writer produces a minimal but valid PDF (Helvetica, multi-page)
so `report.pdf` always exists even on a bare Python install.
"""

from __future__ import annotations

import os
import shutil
import subprocess

_PAGE_W, _PAGE_H = 595, 842          # A4 in points
_MARGIN = 50
_LINE = 14
_FONT = 11
_MAX_LINES = int((_PAGE_H - 2 * _MARGIN) / _LINE)
_MAX_CHARS = 95


def _esc(s: str) -> str:
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(text: str):
    for raw in text.split("\n"):
        raw = raw.replace("\t", "    ").rstrip()
        # strip non-latin-1 (emoji etc.) so the base PDF font can render it
        raw = raw.encode("latin-1", "replace").decode("latin-1")
        if not raw:
            yield ""
            continue
        while len(raw) > _MAX_CHARS:
            cut = raw.rfind(" ", 0, _MAX_CHARS)
            cut = cut if cut > 40 else _MAX_CHARS
            yield raw[:cut]
            raw = raw[cut:].lstrip()
        yield raw


def _paginate(lines):
    page, pages = [], []
    for ln in lines:
        page.append(ln)
        if len(page) >= _MAX_LINES:
            pages.append(page)
            page = []
    if page:
        pages.append(page)
    return pages or [[""]]


def write_text_pdf(lines, path: str) -> str:
    """Write a minimal valid multi-page PDF from text lines (no dependencies)."""
    pages = _paginate(list(lines))
    objects = []           # object bodies (1-indexed via order)
    # 1: Catalog, 2: Pages, 3: Font, then per page: content + page objects
    n_pages = len(pages)
    font_obj = 3
    # page objects start at 4, content objects after pages
    page_obj_ids = [4 + i for i in range(n_pages)]
    content_obj_ids = [4 + n_pages + i for i in range(n_pages)]

    catalog = "<< /Type /Catalog /Pages 2 0 R >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_obj_ids)
    pages_obj = f"<< /Type /Pages /Count {n_pages} /Kids [{kids}] >>"
    font = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

    objects.append(catalog)      # obj 1
    objects.append(pages_obj)    # obj 2
    objects.append(font)         # obj 3

    # page objects
    for i in range(n_pages):
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Resources << /Font << /F1 {font_obj} 0 R >> >> "
            f"/Contents {content_obj_ids[i]} 0 R >>")
    # content streams
    for i, page in enumerate(pages):
        y = _PAGE_H - _MARGIN
        parts = ["BT", f"/F1 {_FONT} Tf", f"{_LINE} TL", f"{_MARGIN} {y} Td"]
        for j, ln in enumerate(page):
            parts.append(f"({_esc(ln)}) Tj")
            parts.append("T*")
        parts.append("ET")
        stream = "\n".join(parts)
        objects.append(f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream")

    # assemble with xref
    out = ["%PDF-1.4"]
    offsets = []
    pos = len(out[0]) + 1
    body = out[0] + "\n"
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        chunk = f"{idx} 0 obj\n{obj}\nendobj\n"
        body += chunk
    xref_pos = len(body)
    n_obj = len(objects) + 1
    body += f"xref\n0 {n_obj}\n0000000000 65535 f \n"
    for off in offsets:
        body += f"{off:010d} 00000 n \n"
    body += (f"trailer\n<< /Size {n_obj} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF")
    with open(path, "wb") as fh:
        fh.write(body.encode("latin-1", "replace"))
    return path


def _try_html_to_pdf(html_path: str, pdf_path: str) -> bool:
    if not html_path or not os.path.isfile(html_path):
        return False
    if shutil.which("wkhtmltopdf"):
        try:
            subprocess.run(["wkhtmltopdf", "-q", html_path, pdf_path], timeout=120,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return os.path.isfile(pdf_path)
        except Exception:
            return False
    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=html_path).write_pdf(pdf_path)
        return os.path.isfile(pdf_path)
    except Exception:
        return False


def _summary_lines(assessment) -> list:
    from .report import summarize
    s = summarize(assessment)
    L = ["VULNSCAN — SECURITY ASSESSMENT REPORT", "=" * 60, "",
         f"Target : {assessment.target}",
         f"Type   : {assessment.kind}   Profile: {assessment.profile}   Mode: {assessment.mode}",
         f"Policy : {assessment.policy.summary()}",
         "", "EXECUTIVE SUMMARY", "-" * 40,
         f"Security score : {s['security_score']}/100",
         f"Findings       : {s['total']}  (critical {s['counts']['critical']}, "
         f"high {s['counts']['high']}, medium {s['counts']['medium']}, "
         f"low {s['counts']['low']}, info {s['counts']['info']})",
         f"Actively exploited (KEV): {s['kev_count']}",
         f"Attack paths   : {s['attack_paths']} (top risk {s['top_attack_risk']}/100)",
         ""]
    if assessment.attack_paths:
        L += ["ATTACK PATHS", "-" * 40]
        for i, p in enumerate(assessment.attack_paths[:8], 1):
            obj = f"  =>  {p.get('objective')}" if p.get("objective") else ""
            L.append(f"{i}. [{p['risk_score']}/100] {p['asset']}{obj}")
            L.append(f"   {p['chain']}")
        L.append("")
    L += ["FINDINGS", "-" * 40]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for i, f in enumerate(sorted(assessment.findings, key=lambda x: order.get(x.severity, 9)), 1):
        L.append(f"{i}. [{f.severity.upper()}] {f.title}")
        L.append(f"   confidence={f.confidence} validation={f.validation} status={f.status}")
        L.append(f"   asset={f.asset}  CWE={f.cwe}  OWASP={f.owasp}"
                 + (f"  CVE={f.cve}" if f.cve else "") + ("  KEV" if f.kev else ""))
        if f.attack:
            L.append(f"   attack: {f.attack}")
        if f.patch:
            L.append(f"   fix: {f.patch}")
        L.append("")
    if assessment.coverage:
        L += ["COVERAGE", "-" * 40] + assessment.coverage.render().split("\n")
    L += ["", "Authorized assessment — detection & validation only. Not a claim of '100% secure'."]
    return L


def write_pdf(assessment, path: str, html_path: str | None = None) -> str:
    """Produce a PDF: rich (html->pdf) if a converter exists, else built-in text PDF."""
    if html_path and _try_html_to_pdf(html_path, path):
        return path
    lines = []
    for ln in _summary_lines(assessment):
        lines.extend(_wrap(ln))
    return write_text_pdf(lines, path)
