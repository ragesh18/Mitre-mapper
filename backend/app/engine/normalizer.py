"""Turns raw log text into a consistent, lowercase, whitespace-collapsed form.
The text is only ever treated as data - it is never executed."""
import re

_QUOTES = re.compile(r"[\"'`]+")
_WS = re.compile(r"\s+")
_TOKEN = re.compile(r"[a-z0-9]+")


def normalize(text: str) -> str:
    text = text.lower().replace("::", " ").replace("\\", "/")
    text = _QUOTES.sub(" ", text)
    return _WS.sub(" ", text).strip()


def tokens(text: str) -> set:
    return set(_TOKEN.findall(text.lower()))
