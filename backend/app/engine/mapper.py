"""Mapping engine: rule/indicator matching + technique-name similarity.

Pure Python (no web/DB dependencies) so it is easy to unit test.
Confidence is a heuristic of THIS tool, not a value published by MITRE.
"""
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .normalizer import normalize, tokens
from .rules import Rule

STOPWORDS = {"of", "the", "and", "or", "to", "a", "an", "in", "for", "with", "via", "from"}
SIMILARITY_CAP = 0.60
RULE_CAP = 0.97


@dataclass
class Match:
    attack_id: str
    name: str
    tactics: List[str]
    confidence: float
    indicators: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)

    def to_dict(self):
        return {**self.__dict__, "confidence": round(self.confidence * 100)}


def _found(ind: str, raw: str, norm: str) -> bool:
    if ind not in raw and ind not in norm:
        return False
    # short plain-word indicators need word boundaries ("lsass" must not match "classassist")
    if len(ind) <= 12 and re.fullmatch(r"[a-z0-9 ._]+", ind):
        return bool(re.search(r"(?<![a-z0-9])" + re.escape(ind) + r"(?![a-z0-9])", raw))
    return True


class Mapper:
    def __init__(self, rules: List[Rule], techniques: Optional[List[dict]] = None):
        self.rules = rules
        self.techniques = techniques or []  # [{"attack_id","name","tactics":[...]}]
        self._by_id = {t["attack_id"]: t for t in self.techniques}
        self._name_tokens = {
            t["attack_id"]: {w for w in tokens(t["name"]) if w not in STOPWORDS} for t in self.techniques
        }

    def map_text(self, text: str, top_n: int = 10) -> List[dict]:
        raw, norm = text.lower(), normalize(text)
        found = {}

        for rule in self.rules:
            hits = [i for i, il in zip(rule.indicators, rule.indicators_lower) if _found(il, raw, norm)]
            if hits:
                conf = min(RULE_CAP, rule.weight + 0.05 * (len(hits) - 1))
                found[rule.attack_id] = Match(rule.attack_id, rule.name, rule.tactics, conf, hits, ["rule"])

        text_tokens = tokens(norm)
        for aid, name_tokens in self._name_tokens.items():
            overlap = name_tokens & text_tokens
            if len(name_tokens) < 2 or len(overlap) < 2 or len(overlap) / len(name_tokens) < 0.67:
                continue
            if aid in found:
                m = found[aid]
                m.methods.append("similarity")
                m.confidence = min(RULE_CAP, m.confidence + 0.03)
            else:
                t = self._by_id[aid]
                conf = SIMILARITY_CAP * len(overlap) / len(name_tokens)
                found[aid] = Match(aid, t["name"], t["tactics"], conf, sorted(overlap), ["similarity"])

        for aid, m in found.items():  # prefer synced MITRE metadata when available
            t = self._by_id.get(aid)
            if t:
                m.name, m.tactics = t["name"], t["tactics"] or m.tactics
        ranked = sorted(found.values(), key=lambda m: (-m.confidence, m.attack_id))
        return [m.to_dict() for m in ranked[:top_n]]
