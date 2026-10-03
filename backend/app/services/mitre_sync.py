"""Downloads MITRE ATT&CK enterprise STIX 2.1 data and upserts techniques into SQLite."""
import json
import urllib.request

from sqlalchemy.orm import Session

from ..core.config import STIX_URL
from ..db.models import Technique

# Minimal offline seed so the tool works before the first sync. Replaced by the full dataset on sync.
SEED = [
    ("T1059.001", "PowerShell", "Execution"), ("T1059.003", "Windows Command Shell", "Execution"),
    ("T1003.001", "LSASS Memory", "Credential Access"), ("T1003.002", "Security Account Manager", "Credential Access"),
    ("T1003.003", "NTDS", "Credential Access"), ("T1110", "Brute Force", "Credential Access"),
    ("T1033", "System Owner/User Discovery", "Discovery"), ("T1082", "System Information Discovery", "Discovery"),
    ("T1087", "Account Discovery", "Discovery"), ("T1016", "System Network Configuration Discovery", "Discovery"),
    ("T1018", "Remote System Discovery", "Discovery"), ("T1046", "Network Service Discovery", "Discovery"),
    ("T1057", "Process Discovery", "Discovery"), ("T1053.005", "Scheduled Task", "Execution,Persistence,Privilege Escalation"),
    ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence,Privilege Escalation"),
    ("T1105", "Ingress Tool Transfer", "Command and Control"), ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
    ("T1070.001", "Clear Windows Event Logs", "Defense Evasion"), ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
    ("T1486", "Data Encrypted for Impact", "Impact"), ("T1490", "Inhibit System Recovery", "Impact"),
    ("T1566.001", "Spearphishing Attachment", "Initial Access"), ("T1190", "Exploit Public-Facing Application", "Initial Access"),
]


def _url(attack_id: str) -> str:
    return "https://attack.mitre.org/techniques/" + attack_id.replace(".", "/") + "/"


def seed_if_empty(db: Session) -> None:
    if db.query(Technique).count():
        return
    for aid, name, tactics in SEED:
        db.add(Technique(attack_id=aid, name=name, tactics=tactics, url=_url(aid), is_subtechnique="." in aid))
    db.commit()


def parse_stix(bundle: dict) -> list:
    out = []
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ref or not ref.get("external_id"):
            continue
        tactics = [p["phase_name"].replace("-", " ").title() for p in o.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        out.append({
            "attack_id": ref["external_id"], "name": o.get("name", ""), "description": o.get("description", ""),
            "tactics": ",".join(tactics), "platforms": ",".join(o.get("x_mitre_platforms", [])),
            "url": ref.get("url") or _url(ref["external_id"]), "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
        })
    return out


def upsert(db: Session, records: list) -> int:
    existing = {t.attack_id: t for t in db.query(Technique).all()}
    for r in records:
        t = existing.get(r["attack_id"])
        if t:
            for k, v in r.items():
                setattr(t, k, v)
        else:
            db.add(Technique(**r))
    db.commit()
    return len(records)


def sync_mitre(db: Session, url: str = STIX_URL, timeout: int = 60) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "mitre-mapping-tool/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL from config
        bundle = json.loads(resp.read().decode("utf-8"))
    return upsert(db, parse_stix(bundle))
