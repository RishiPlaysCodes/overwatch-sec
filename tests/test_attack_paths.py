from core.findings import Finding
from attack_paths import mitre, correlation


def _mk():
    return [
        Finding(id="web.sqli", title="SQL Injection", severity="high", asset="app.x.com",
                cvss=8.0),
        Finding(id="cloud.iam_wildcard", title="Wildcard IAM", severity="high", asset="app.x.com"),
        Finding(id="web.header.csp", title="Missing CSP", severity="medium", asset="app.x.com"),
    ]


def test_mitre_annotation():
    fs = _mk()
    mitre.annotate(fs)
    ids = {m for f in fs for m in f.mitre}
    assert "T1190" in ids          # sqli -> exploit public-facing app
    assert "T1078" in ids          # iam wildcard -> valid accounts


def test_build_paths_and_risk():
    fs = _mk()
    mitre.annotate(fs)
    paths = correlation.build_paths(fs, "app.x.com")
    assert paths
    top = paths[0]
    assert top["asset"] == "app.x.com"
    assert top["risk_score"] > 0
    assert top["length"] >= 1
    assert "Internet ->" in top["chain"]


def test_kev_raises_risk():
    fs = [Finding(id="web.cve", title="CVE", severity="high", asset="a", kev=True, cvss=9.8)]
    mitre.annotate(fs)
    paths = correlation.build_paths(fs, "a")
    assert paths[0]["risk_score"] >= 50
