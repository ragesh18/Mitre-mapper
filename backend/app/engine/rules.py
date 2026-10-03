import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class Rule:
    attack_id: str
    name: str
    tactics: List[str]
    indicators: List[str]
    weight: float = 0.7  # confidence when a single indicator matches
    indicators_lower: List[str] = field(init=False)

    def __post_init__(self):
        self.indicators_lower = [i.lower() for i in self.indicators]


def load_rules(path: Path) -> List[Rule]:
    with open(path, encoding="utf-8") as f:
        return [Rule(**r) for r in json.load(f)]
