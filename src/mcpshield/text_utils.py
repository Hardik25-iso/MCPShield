"""Shared text utilities: normalization, hidden-text discovery, pattern matching, hashing.

Pure functions only. Patterns are passed in by callers; this module never reads config or policies.
"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

ZERO_WIDTH = frozenset("​‌‍⁠﻿᠎­")

# Cyrillic and Greek letters that render like Latin ones.
HOMOGLYPHS: dict[str, str] = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "Х": "X",
    "ο": "o",
    "α": "a",
    "ν": "v",
    "ρ": "p",
    "τ": "t",
    "Ι": "I",
    "Ο": "O",
}
_LATIN_TO_HOMOGLYPH = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "y": "у", "x": "х", "i": "і"}

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_WORD_RE = re.compile(r"[a-z0-9]+")


class _Spec(Protocol):
    label: str
    regex: str
    weight: float


@dataclass(frozen=True)
class CompiledPattern:
    label: str
    pattern: re.Pattern[str]
    weight: float


@dataclass(frozen=True)
class Hit:
    label: str
    text: str
    span: tuple[int, int]
    weight: float


# ------------------------------------------------------------ normalization and hidden text


def strip_zero_width(text: str) -> str:
    return "".join(ch for ch in text if ch not in ZERO_WIDTH)


def map_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in text)


def normalize(text: str) -> str:
    return map_homoglyphs(strip_zero_width(unicodedata.normalize("NFKC", text)))


def find_zero_width(text: str) -> list[int]:
    return [i for i, ch in enumerate(text) if ch in ZERO_WIDTH]


def find_homoglyphs(text: str) -> list[tuple[int, str]]:
    """Homoglyphs inside otherwise-Latin words (mixed-script tokens), with their positions."""
    found: list[tuple[int, str]] = []
    for match in re.finditer(r"\w+", text):
        word = match.group(0)
        has_latin = any("a" <= c.lower() <= "z" for c in word)
        glyphs = [(match.start() + i, c) for i, c in enumerate(word) if c in HOMOGLYPHS]
        if has_latin and glyphs:
            found.extend(glyphs)
    return found


def decode_base64_blobs(text: str, min_printable: float = 0.9) -> list[tuple[tuple[int, int], str]]:
    blobs = []
    for match in _BASE64_RE.finditer(text):
        try:
            decoded = base64.b64decode(match.group(0), validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded) / max(len(decoded), 1)
        if decoded and printable >= min_printable:
            blobs.append((match.span(), decoded))
    return blobs


def find_html_comments(text: str) -> list[tuple[tuple[int, int], str]]:
    return [(m.span(), m.group(1).strip()) for m in _HTML_COMMENT_RE.finditer(text)]


def find_tagged_blocks(text: str, tags: Iterable[str]) -> list[tuple[tuple[int, int], str, str]]:
    blocks: list[tuple[tuple[int, int], str, str]] = []
    for tag in tags:
        pattern = re.compile(rf"<\s*{re.escape(tag)}\s*>(.*?)<\s*/\s*{re.escape(tag)}\s*>", re.S | re.I)
        blocks.extend((m.span(), tag, m.group(1).strip()) for m in pattern.finditer(text))
    return blocks


def reveal(text: str) -> str:
    """Text as a capable model would read it: normalized, with base64 and comment contents exposed."""
    clean = normalize(text)
    extras = [decoded for _, decoded in decode_base64_blobs(clean)]
    extras += [content for _, content in find_html_comments(clean)]
    return "\n".join([clean, *extras])


def obfuscate(text: str, encoding: str) -> str:
    """Encode a payload the way the malicious server hides it (inverse of `reveal`)."""
    if encoding == "important_tag":
        return f"<IMPORTANT>{text}</IMPORTANT>"
    if encoding == "zero_width":
        return "​".join(text)
    if encoding == "base64":
        return base64.b64encode(text.encode()).decode()
    if encoding == "homoglyph":
        return "".join(_LATIN_TO_HOMOGLYPH.get(ch, ch) for ch in text)
    if encoding == "html_comment":
        return f"<!-- {text} -->"
    return text


# ------------------------------------------------------------ pattern matching


def compile_patterns(specs: Sequence[_Spec]) -> list[CompiledPattern]:
    return [CompiledPattern(s.label, re.compile(s.regex, re.I | re.S), s.weight) for s in specs]


def instruction_hits(text: str, patterns: Sequence[CompiledPattern]) -> list[Hit]:
    hits: list[Hit] = []
    for p in patterns:
        hits.extend(Hit(p.label, m.group(0), m.span(), p.weight) for m in p.pattern.finditer(text))
    return hits


def merge_spans(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def sentence_spans(text: str, positions: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    """Expand match spans to the enclosing sentence or line so quarantine removes whole instructions."""
    bounds = [m.span() for m in re.finditer(r"[^.!?\n]+[.!?]?", text)]
    out = []
    for start, end in positions:
        covering = [b for b in bounds if b[0] < end and b[1] > start]
        out.append((min(b[0] for b in covering), max(b[1] for b in covering)) if covering else (start, end))
    return merge_spans(out)


# ------------------------------------------------------------ hashing, tokens, diffs


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tokenize(text: str) -> list[str]:
    return _WORD_RE.findall(normalize(text).lower())


def unified_diff(old: str, new: str, label: str = "description") -> str:
    lines = difflib.unified_diff(
        old.splitlines(), new.splitlines(), fromfile=f"{label} (pinned)", tofile=f"{label} (current)", lineterm=""
    )
    return "\n".join(lines)


def shingles(text: str, n: int = 5) -> set[str]:
    tokens = tokenize(text)
    return {" ".join(tokens[i : i + n]) for i in range(max(len(tokens) - n + 1, 1))}


def jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if a and b else 0.0
