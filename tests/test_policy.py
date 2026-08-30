from core import config
from core.policy import Policy


def test_defaults_are_safe():
    p = Policy()
    assert p.passive and p.safe_active
    assert not p.validation and not p.intrusive and not p.destructive
    assert not p.dos and not p.social_engineering
    assert p.max_level() == "safe_active"


def test_bugbounty_policy_is_conservative():
    p = config.load_policy("bugbounty", "fast")
    assert not p.intrusive and not p.destructive and not p.dos


def test_redteam_never_intrusive_or_destructive_by_default():
    p = config.load_policy("redteam", "deep")
    assert p.validation is True
    assert p.intrusive is False        # regression guard for the inline-comment bug
    assert p.destructive is False


def test_lab_may_be_intrusive_but_not_destructive_by_default():
    p = config.load_policy("lab", "deep")
    assert p.intrusive is True
    assert p.destructive is False


def test_hard_clamp_blocks_destructive_outside_lab():
    # even if a config tries to enable destructive under bug_bounty, it's clamped off
    p = Policy.from_dict({"authorization": "bug_bounty",
                          "testing": {"intrusive": True, "destructive": True}})
    assert p.intrusive is False
    assert p.destructive is False


def test_tiny_yaml_inline_comment_stripping():
    d = config._tiny_yaml("testing:\n  intrusive: false  # keep off\n  validation: true\n")
    assert d["testing"]["intrusive"] is False
    assert d["testing"]["validation"] is True


def test_tiny_yaml_lists():
    d = config._tiny_yaml("scanners:\n  - recon\n  - web\nname: x\n")
    assert d["scanners"] == ["recon", "web"]
    assert d["name"] == "x"


def test_redact():
    from core.policy import redact
    assert redact("token=SECRET123 here", ["SECRET123"]) == "token=«redacted» here"
