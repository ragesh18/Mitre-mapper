import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.core.config import RULES_PATH  # noqa: E402
from backend.app.engine.mapper import Mapper  # noqa: E402
from backend.app.engine.rules import load_rules  # noqa: E402
from backend.app.services.mitre_sync import SEED, parse_stix  # noqa: E402

TECHS = [{"attack_id": a, "name": n, "tactics": t.split(",")} for a, n, t in SEED]
M = Mapper(load_rules(RULES_PATH), TECHS)


def ids(text):
    return [r["attack_id"] for r in M.map_text(text)]


def test_powershell():
    assert ids("powershell.exe -enc SGVsbG8=")[0] == "T1059.001"


def test_mimikatz_lsass():
    r = M.map_text('mimikatz.exe "sekurlsa::logonpasswords"')[0]
    assert r["attack_id"] == "T1003.001" and r["tactics"] == ["Credential Access"] and r["confidence"] >= 85


def test_whoami():
    assert "T1033" in ids("cmd.exe /c whoami")


def test_similarity_by_name():
    r = [x for x in M.map_text("attacker ran system information discovery") if x["attack_id"] == "T1082"]
    assert r and "similarity" in r[0]["methods"]


def test_word_boundary_no_false_positive():
    assert "T1003.001" not in ids("the classassist module loaded")


def test_benign_text_no_match():
    assert M.map_text("user opened a document and printed it") == []


def test_commands_are_only_text():
    assert isinstance(M.map_text("rm -rf / ; <script>alert(1)</script>"), list)


def test_parse_stix_skips_revoked():
    bundle = {"objects": [
        {"type": "attack-pattern", "name": "A", "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
         "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "defense-evasion"}]},
        {"type": "attack-pattern", "revoked": True, "name": "B", "external_references": [{"source_name": "mitre-attack", "external_id": "T9998"}]},
    ]}
    out = parse_stix(bundle)
    assert len(out) == 1 and out[0]["tactics"] == "Defense Evasion"
