"""Purple-team detection-verification tests."""
from core.findings import Finding
from purple import verification


def _fs():
    return [Finding(id="web.sqli", title="SQLi", severity="high", asset="x", validation="validated"),
            Finding(id="web.header.csp", title="Missing CSP", severity="medium", asset="x")]


def test_no_telemetry_is_all_gaps():
    r = verification.verify(_fs(), None)
    assert r["summary"]["gaps"] == r["summary"]["techniques_considered"]
    assert r["summary"]["detection_rate"] == 0
    assert r["summary"]["telemetry_provided"] is False


def test_telemetry_marks_detected():
    tel = {"detections": [{"technique": "T1190", "alerted": True, "rule": "WAF-SQLi", "latency_seconds": 9}]}
    r = verification.verify(_fs(), tel)
    sqli = [row for row in r["rows"] if row["finding_id"] == "web.sqli"][0]
    assert sqli["detected"] is True
    assert sqli["detection_gap"] is False
    assert sqli["detection_rule"] == "WAF-SQLi"


def test_blocked_findings_excluded():
    f = Finding(id="web.xss.reflected", title="XSS", asset="x", validation="blocked_by_policy")
    r = verification.verify([f], None)
    assert r["summary"]["techniques_considered"] == 0   # no test activity occurred


def test_gap_has_recommendation():
    r = verification.verify([Finding(id="web.sqli", title="SQLi", asset="x", validation="validated")], None)
    assert r["rows"][0]["recommendation"]
