from core.scope import Scope


def test_wildcard_and_exact():
    s = Scope(allowed=["example.com", "*.example.com"])
    assert s.allows("example.com")
    assert s.allows("api.example.com")
    assert s.allows("https://deep.sub.example.com/x")
    assert not s.allows("evil.com")


def test_exclusions_win():
    s = Scope(allowed=["*.example.com"], excluded=["admin.example.com"])
    assert s.allows("api.example.com")
    assert not s.allows("admin.example.com")


def test_cidr_scope():
    s = Scope(allowed=["10.0.0.0/24"])
    assert s.allows("10.0.0.5")
    assert not s.allows("10.0.1.5")
    assert not s.allows("192.168.0.1")


def test_single_target_default():
    s = Scope.single("https://shop.example.com/cart")
    assert s.allows("shop.example.com")
    assert s.allows("api.example.com")     # same apex
    assert not s.allows("attacker.net")


def test_filter_partition():
    s = Scope(allowed=["example.com", "*.example.com"])
    ins, outs = s.filter(["api.example.com", "evil.com", "example.com"])
    assert set(ins) == {"api.example.com", "example.com"}
    assert outs == ["evil.com"]
