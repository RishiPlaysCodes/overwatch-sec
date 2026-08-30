from core.target_detector import detect
from core.findings import Finding, dedupe, sort_key


def test_detect_kinds():
    assert detect("example.com")["kind"] == "recon"
    assert detect("https://x.com/api/v1/u")["kind"] == "api"
    assert detect("https://x.com/page")["kind"] == "web"
    assert detect("10.0.0.5")["kind"] == "network"
    assert detect("192.168.0.0/16")["kind"] == "network"
    assert detect("nginx:1.21")["kind"] == "container"
    assert detect("app.apk")["kind"] == "mobile"
    assert detect("aws")["kind"] == "cloud"


def test_finding_from_legacy_infers_epistemics():
    d = {"id": "web.sqli", "title": "SQL Injection", "severity": "high",
         "evidence": "CVE-2021-44228 CVSS 9.8 ACTIVELY EXPLOITED (CISA KEV)"}
    f = Finding.from_legacy(d, asset="api.x.com")
    assert f.severity == "high"
    assert f.kev is True
    assert f.cvss == 9.8
    assert f.cve == "CVE-2021-44228"
    assert f.confidence == "high_confidence"


def test_finding_fingerprint_stable_and_dedupe():
    a = Finding(id="web.xss", title="XSS", asset="x.com")
    b = Finding(id="web.xss", title="XSS (dup)", asset="x.com")
    assert a.fingerprint() == b.fingerprint()
    assert len(dedupe([a, b])) == 1


def test_sort_key_orders_critical_first_and_kev():
    lo = Finding(id="a", title="a", severity="low")
    hi = Finding(id="b", title="b", severity="critical")
    kev = Finding(id="c", title="c", severity="high", kev=True)
    ordered = sorted([lo, kev, hi], key=sort_key)
    assert ordered[0].severity == "critical"
