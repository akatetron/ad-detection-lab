"""Regression tests: every rule must fire on all attack samples and stay quiet on benign samples."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from sigma_eval import load_events, load_rule, matches  # noqa: E402

RULES = sorted((ROOT / "rules" / "sigma").glob("*.yml"))


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_rule_has_attack_mapping(rule_path):
    rule = load_rule(rule_path)
    assert any(t.startswith("attack.t") for t in rule.get("tags", [])), "rule needs an ATT&CK technique tag"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_conversions_exist(rule_path):
    for ext, folder in (("kql", "kql"), ("spl", "spl")):
        assert (ROOT / "rules" / folder / f"{rule_path.stem}.{ext}").exists(), f"missing {ext} conversion"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_fires_on_attack(rule_path):
    rule = load_rule(rule_path)
    events = load_events(ROOT / "tests" / "data" / rule_path.stem / "attack.jsonl")
    assert events, "no attack samples"
    missed = [e for e in events if not matches(rule, e)]
    assert not missed, f"rule missed {len(missed)} attack event(s): {missed}"


@pytest.mark.parametrize("rule_path", RULES, ids=lambda p: p.stem)
def test_quiet_on_benign(rule_path):
    rule = load_rule(rule_path)
    events = load_events(ROOT / "tests" / "data" / rule_path.stem / "benign.jsonl")
    assert events, "no benign samples"
    noisy = [e for e in events if matches(rule, e)]
    assert not noisy, f"rule fired on {len(noisy)} benign event(s): {noisy}"
