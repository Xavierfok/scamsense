import analyzer
import rules


def cats(text):
    return {f.category for f in rules.analyse(text)["flags"]}


def test_delivery_scam_is_flagged():
    text = "SingPost: pay $1.99 fee within 24 hours: https://singpost-redelivery.top/pay"
    r = rules.analyse(text)
    assert "Pressure / urgency" in cats(text)
    assert any("domain ending" in f.category for f in r["flags"])
    assert rules.verdict_for(r["score"]) in ("Suspicious", "Likely scam")


def test_bank_otp_scam_is_likely_scam():
    text = "DBS Alert: your account will be suspended. Verify at bit.ly/dbs-secure and enter the OTP. Do not tell anyone."
    r = rules.analyse(text)
    assert "Asks for codes or passwords" in cats(text)
    assert any("Shortened" in f.category for f in r["flags"])
    assert rules.verdict_for(r["score"]) == "Likely scam"


def test_link_detection():
    assert rules.find_links("go to bit.ly/x now") == ["bit.ly/x"]
    assert rules.find_links("visit www.dbs.com.sg today") == ["www.dbs.com.sg"]
    assert rules.find_links("email me at john@gmail.com") == []


def test_defang_makes_links_unclickable():
    assert rules.defang("go to https://singpost-redelivery.top/pay now") == "go to hxxps://singpost-redelivery[.]top/pay now"
    assert rules.defang("bit.ly/abc") == "bit[.]ly/abc"
    assert rules.defang("no links here") == "no links here"


def test_delivery_fee_scam_is_likely_scam():
    text = ("SingPost: Your parcel is on hold due to an unpaid $1.99 delivery fee. "
            "Pay within 24 hours or it will be returned: https://singpost-redelivery.top/pay")
    assert rules.verdict_for(rules.analyse(text)["score"]) == "Likely scam"


def test_job_scam():
    assert "Too-good-to-be-true job offer" in cats("Earn $300 per day liking videos, part-time task")


def test_normal_message_is_safe():
    r = rules.analyse("Are we still on for lunch at 12:30 tomorrow?")
    assert r["flags"] == []
    assert rules.verdict_for(r["score"]) == "Probably safe"


def test_score_capped_at_100():
    text = ("URGENT police: transfer the money via bitcoin, give your OTP and password, "
            "install AnyDesk, don't tell anyone, bit.ly/x, earn $500 per day")
    assert rules.analyse(text)["score"] == 100


def test_redact_masks_numbers_and_emails_but_keeps_links():
    out = rules.redact("Card 4111 1111 1111 1234, call +65 9123 4567, mail john.doe@gmail.com, go to bit.ly/abc123")
    assert "4111" not in out and "•234" in out
    assert "9123" not in out
    assert "john.doe" not in out and "@gmail.com" in out
    assert "bit.ly/abc123" in out


def test_rules_only_mode_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    res = analyzer.check_message("Your account will be suspended, send the OTP now")
    assert res["mode"] == "rules"
    assert res["verdict"] in ("Suspicious", "Likely scam")
    assert res["what_to_do"]


def test_safety_floor_overrides_fooled_ai(monkeypatch):
    fooled = {"verdict": "Probably safe", "risk_score": 5, "scam_type": "None detected",
              "red_flags": [], "explanation": "Looks fine.", "what_to_do": ["Relax"]}
    monkeypatch.setattr(analyzer, "ask_ai", lambda *a, **k: fooled)
    res = analyzer.check_message("Police here. Transfer the money immediately, give us your OTP, don't tell anyone. bit.ly/x")
    assert res["verdict"] == "Suspicious"
    assert res.get("floor_applied")


def test_bad_ai_output_is_sanitised(monkeypatch):
    monkeypatch.setattr(analyzer, "ask_ai", lambda *a, **k: {"verdict": "banana", "risk_score": "lots", "red_flags": "x"})
    res = analyzer.check_message("hello")
    assert res["verdict"] in analyzer.VERDICTS
    assert 0 <= res["score"] <= 100
    assert res["red_flags"] == []
