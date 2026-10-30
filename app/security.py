import re
from dataclasses import dataclass


SENSITIVE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("EMAIL", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("SSN", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")),
    (
        "CARD",
        re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
    ),
]

INJECTION_PATTERNS = [
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b", re.I),
    re.compile(r"\b(disregard|override|forget)\s+(?:the\s+)?(?:system|developer|safety)\s+(?:prompt|instructions|rules)\b", re.I),
    re.compile(r"\breveal\s+(?:your\s+)?(?:system\s+prompt|hidden\s+instructions|secrets)\b", re.I),
    re.compile(r"\bdeveloper\s+message\s*:", re.I),
    re.compile(r"<\s*system\s*>", re.I),
]

UNSAFE_OUTPUT_PATTERNS = [
    re.compile(r"\b(ransomware|credential stealer|keylogger)\b", re.I),
    re.compile(r"\b(exfiltrate|steal)\s+(?:passwords|credentials|private keys)\b", re.I),
]


@dataclass
class RedactionResult:
    text: str
    replacements: dict[str, str]
    count: int

    def restore(self, text: str) -> str:
        for placeholder, original in self.replacements.items():
            text = text.replace(placeholder, original)
        return text


def _is_luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact_pii(text: str) -> RedactionResult:
    replacements: dict[str, str] = {}
    labels: dict[tuple[str, str], str] = {}
    counts: dict[str, int] = {}

    for label, pattern in SENSITIVE_PATTERNS:
        def replace(match: re.Match[str], kind: str = label) -> str:
            original = match.group(0)
            if kind == "CARD" and not _is_luhn_valid(original):
                return original
            key = (kind, original)
            if key not in labels:
                counts[kind] = counts.get(kind, 0) + 1
                placeholder = f"[REDACTED_{kind}_{counts[kind]}]"
                labels[key] = placeholder
                replacements[placeholder] = original
            return labels[key]

        text = pattern.sub(replace, text)

    return RedactionResult(text, replacements, len(replacements))


def detect_prompt_injection(text: str) -> bool:
    return any(pattern.search(text) for pattern in INJECTION_PATTERNS)


def violates_output_policy(text: str) -> bool:
    return any(pattern.search(text) for pattern in UNSAFE_OUTPUT_PATTERNS)
