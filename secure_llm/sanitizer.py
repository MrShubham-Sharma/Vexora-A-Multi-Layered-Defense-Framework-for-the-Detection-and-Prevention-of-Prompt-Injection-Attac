"""
Layer 1 — Input Sanitization

Fast, cheap, first-pass filter. Uses heuristic string matching and regex
logic to catch KNOWN adversarial syntax patterns before any expensive
processing (LLM call, classifier inference) happens.

This layer is intentionally conservative in scope: it is good at catching
"known bad" surface patterns (leaked delimiters, encoding tricks, classic
jailbreak phrasing) but it is NOT a semantic defense. It should always be
paired with Layer 2 (context encapsulation) and Layer 3 (intent classifier).
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List

# ---------------------------------------------------------------------------
# Active Learning Feedback Loop
# ---------------------------------------------------------------------------
_REPORTED_FEEDBACK_ATTACKS: set[str] = set()

def _load_feedback_cache():
    global _REPORTED_FEEDBACK_ATTACKS
    feedback_paths = [
        Path("feedback_adversarial.txt"),
        Path(__file__).resolve().parent / "feedback_adversarial.txt",
        Path(__file__).resolve().parent.parent / "feedback_adversarial.txt",
    ]
    for p in feedback_paths:
        if p.exists():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#") and len(line) >= 8:
                            _REPORTED_FEEDBACK_ATTACKS.add(line)
            except Exception:
                pass

_load_feedback_cache()

def register_feedback_sample(sample: str) -> None:
    """Dynamically register a reported adversarial attack sample into active memory."""
    sample = (sample or "").strip().lower()
    if sample and not sample.startswith("#") and len(sample) >= 8:
        _REPORTED_FEEDBACK_ATTACKS.add(sample)



class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class SanitizationFinding:
    rule_name: str
    severity: Severity
    matched_text: str
    description: str


@dataclass
class SanitizationResult:
    original_text: str
    cleaned_text: str
    findings: List[SanitizationFinding] = field(default_factory=list)
    blocked: bool = False

    @property
    def is_suspicious(self) -> bool:
        return len(self.findings) > 0


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
# Each rule: (name, compiled regex, severity, human description)
# Patterns are deliberately broad; false positives are cheap here because
# this layer only *flags/blocks*, it never silently rewrites meaning.

_INSTRUCTION_OVERRIDE_PATTERNS = [
    (
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override|bypass|drop|cancel|negate|stop\s+following|disobey|suspend|pause|mute|disable)\b.{0,40}\b"
            r"(previous|prior|above|earlier|all|system|your|core|base|initial|default)\b.{0,40}\b"
            r"(instructions?|rules?|prompts?|guidelines?|context|constraints?|directives?|programming|safeguards?|filters?|restrictions?)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to override or discard prior system instructions.",
    ),
    (
        "role_reassignment",
        re.compile(
            r"\b(you\s+are\s+now|act\s+as|pretend\s+you\s+are|roleplay\s+as|adopt\s+the\s+persona\s+of|from\s+now\s+on\s+you\s+are|assume\s+the\s+role\s+of|become)\b.{0,50}\b"
            r"(dan|jailbreak|jailbroken|unfiltered|unrestricted|developer\s+mode|chaos|evil|god\s+mode|root|admin|hacker|unbound|limitless|based|(?:no|without|zero|drop)\s+(?:content|ethical|safety|policy|moral|behavioral)?\s*(?:rules?|restrictions?|constraints?|filters?|guidelines?))\b|"
            r"\b(do\s+anything\s+now|no\s+content\s+rules|without\s+any\s+restrictions|without\s+(?:any\s+)?ethical\s+constraints|break\s+all\s+rules|ignore\s+safety|disable\s+safety|answer\s+freely)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to reassign the model's role/persona to bypass alignment.",
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"\b(?:what\s+(?:is|are|was|were|'s)|what\s+were\s+the|repeat|reveal|print|show|output|leak|display|dump|tell\s+me|echo|summarize|extract|read|provide|share|write\s+out|give\s+me|disclose|state|copy|describe|explain)\b.{0,50}\b"
            r"(?:(?:your|the\s+(?:model|assistant|ai|system)'?s?)\s+(?:system|initial|core|base|hidden|secret|developer|internal|backend)?\s*(?:instructions?|prompts?|rules?|guidelines?|directives?|configuration)|"
            r"(?:the\s+)?(?:system|initial|core|base|hidden|secret|developer|internal|backend)\s+(?:instructions?|prompts?|rules?|guidelines?|directives?|messages?|configuration|setup)|"
            r"(?:initial|original|starting|base)\s+prompt\s+(?:given|provided)\s+to\s+you)\b|"
            r"\bwhat\s+(?:is|are|was|were|'s)\b.{0,40}\b(?:your|the)?\s*(?:system|initial|core|base|hidden|secret|developer|internal)\s*(?:instructions?|prompts?|rules?|guidelines?|directives?|configuration|setup)\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to extract the system prompt, instructions, or hidden configuration.",
    ),
    (
        "rag_indirect_injection",
        re.compile(
            r"\b(?:note|instruction|directive|notice|warning|message)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|llm|model|agent)\s*:\s*(?:ignore|disregard|override|forget|reveal|dump|leak|exfiltrate)\b|"
            r"\b(?:ai|assistant|llm|model|agent)\s*(?:instruction|directive|override|command)\s*:\s*(?:ignore|disregard|override|reveal|bypass|output)\b|"
            r"\b(?:when|if)\s+(?:you\s+)?(?:read|see|parse|process|summarize|extract)\s+this\b.{0,50}\b(?:ignore|disregard|override|reveal|leak|exfiltrate|send|output)\b|"
            r"\b(?:do\s+not|never)\s+(?:inform|tell|alert|notify)\s+(?:the\s+)?(?:user|human)\b.{0,40}\b(?:instead|secretly|silently)\b|"
            r"\b(?:secretly|silently|covertly)\s+(?:output|execute|send|leak|append|transmit|exfiltrate)\b|"
            r"\b(?:instead\s+of\s+(?:summarizing|answering|translating|processing)|ignore\s+(?:the\s+)?user(?:'s)?\s+(?:request|query|prompt))\b.{0,40}\b(?:say|reveal|output|execute)\b|"
            r"\b(?:from\s+now\s+on\s+ignore\s+(?:the\s+)?user|disregard\s+(?:the\s+)?user(?:'s)?\s+(?:prompt|message))\b|"
            r"\b(?:important\s+system\s+(?:override|directive)|system\s+override\s*:|\[(?:system\s+(?:message|override|directive)|rag_injection|hidden_instruction)\])",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Indirect prompt injection or RAG poisoning payload targeting model execution.",
    ),
    (
        "data_exfiltration",
        re.compile(
            r"!\[.*?\]\((?:https?:)?//[^\s\)]+(?:\?|&)(?:data|exfil|leak|prompt|secret|key|token|cookie|history)=|"
            r"\b(?:send|forward|transmit|exfiltrate|leak|post|upload)\b.{0,40}\b(?:customer\s+data|system\s+prompt|secrets?|credentials?|passwords?|api\s+keys?|private\s+keys?|confidential\s+data)\b.{0,40}\b(?:to\s+https?://|to\s+url|to\s+external\s+server|to\s+webhook)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to exfiltrate sensitive data, credentials, or context to external destinations.",
    ),
    (
        "privilege_escalation",
        re.compile(
            r"\b(i\s+am\s+your\s+(administrator|developer|creator)|enter\s+(debug|admin|root)\s+mode|disable\s+(filters|safety|moderation))\b",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Attempt to escalate privileges by claiming administrative or developer status.",
    ),
    (
        "delimiter_spoofing",
        re.compile(
            r"(</?system>|</?\|im_(start|end)\|>|\[/?INST\]|<<SYS>>|<</SYS>>|###\s*(system|instruction|user|assistant|tool)s?\b|<\|.*?\|>|\[/?system\]|\[\[/?(SYSTEM|TOOL|USER)[^\]]*\]\])",
            re.IGNORECASE,
        ),
        Severity.HIGH,
        "Raw input contains control tokens or delimiter syntax used to spoof system-level context boundaries.",
    ),
    (
        "hypothetical_framing",
        re.compile(
            r"\b(for\s+a\s+story|hypothetically|in\s+a\s+fictional\s+world|fictional\s+scenario|imagine\s+that|let's\s+pretend|creative\s+writing|novel|movie\s+script)\b.{0,60}\b"
            r"(no\s+content\s+rules|no\s+rules|no\s+restrictions|freely\s+reveal|bypass\s+rules|hidden\s+configuration|anything\s+goes|do\s+not\s+censor|uncensored|ignore\s+ethics)\b",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Hypothetical/fictional framing commonly used to elicit restricted content indirectly.",
    ),
    (
        "encoding_smuggling",
        re.compile(r"\\u[0-9a-fA-F]{4}|(?:%[0-9a-fA-F]{2}){3,}"),
        Severity.MEDIUM,
        "Unicode escape or percent-encoding sequences that may smuggle instructions past naive string filters.",
    ),
    (
        "refusal_suppression",
        re.compile(
            r"\b(?:do\s+not\s+(?:use|say|include|write|respond\s+with)|never\s+say|avoid\s+saying)\b.{0,40}\b"
            r"(?:sorry|cannot|unable|apologize|against\s+my|guidelines|as\s+an\s+ai|language\s+model|i\s+can't|my\s+safety\s+policy)\b",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Attempt to suppress model's built-in refusal and apology mechanisms.",
    ),
    (
        "prefix_injection",
        re.compile(
            r"\b(start\s+your\s+response\s+with|begin\s+with|reply\s+starting\s+with)\b\s*[\"']?(sure|yes|absolutely|here\s+is|of\s+course|i\s+can|okay)[\"']?",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Attempt to force a positive affirmation prefix to bypass alignment.",
    ),
    (
        "adversarial_word_salad",
        re.compile(
            r"(?:\b(?:jailbreak|dan\s+mode|unfiltered\s+mode|unrestricted\s+ai|bypass\s+safety|break\s+all\s+rules|disable\s+safety\s+filters)\b.*?){2,}",
            re.IGNORECASE,
        ),
        Severity.MEDIUM,
        "Multiple explicit adversarial jailbreak signatures detected in proximity.",
    ),
]


def _contains_zero_width_or_bidi_chars(text: str) -> bool:
    """Detects zero-width and bidirectional-override characters often used
    to visually hide or reorder injected instructions."""
    suspicious_categories = {"Cf"}  # Format characters (includes ZWSP, RLO, etc.)
    suspicious_codepoints = {
        "\u200b",  # zero-width space
        "\u200c",  # zero-width non-joiner
        "\u200d",  # zero-width joiner
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi overrides
        "\ufeff",  # BOM
    }
    for ch in text:
        if ch in suspicious_codepoints:
            return True
        if unicodedata.category(ch) in suspicious_categories:
            return True
    return False


def _looks_like_base64_payload(text: str, min_len: int = 40) -> List[str]:
    """Flags long base64-looking tokens that decode cleanly to text, which
    is a common way to smuggle instructions past keyword filters."""
    hits = []
    for token in re.findall(r"[A-Za-z0-9+/=]{%d,}" % min_len, text):
        try:
            decoded = base64.b64decode(token, validate=True)
            decoded_text = decoded.decode("utf-8")
            if decoded_text.isprintable():
                hits.append(token)
        except Exception:
            continue
    return hits


def sanitize(
    text: str,
    block_on_high_severity: bool = True,
    source: Optional[str] = None
) -> SanitizationResult:
    """
    Run all heuristic/regex checks against `text`.

    Args:
        text: raw user input or retrieved RAG context.
        block_on_high_severity: if True, any HIGH severity finding sets
            `result.blocked = True`, signalling the pipeline to short-circuit
            before the input ever reaches the LLM.
        source: optional identifier (e.g. 'RAG: reviews.acme.com') indicating
            where this text originated.

    Returns:
        SanitizationResult with findings and a (lightly) normalized copy of
        the text. Normalization only strips invisible/control characters —
        it never rewrites the user's actual words, since that could mask
        attacks from the downstream classifier.
    """
    findings: List[SanitizationFinding] = []
    prefix = f"[{source}] " if source else ""
    trimmed = text.strip()

    # Detect meta-inquiries asking definition/meaning about injection phrases
    is_meta_inquiry = bool(re.search(
        r"^\s*(?:what\s+(?:does|is|are|means?)|explain\s+(?:the\s+meaning\s+of|what|why)|why\s+(?:do|does|would)|definition\s+of|meaning\s+of)\b",
        trimmed,
        re.IGNORECASE
    )) and bool(re.search(r"['\"].*?['\"]|\b(?:mean|meaning|term|phrase|concept|research|paper)\b", trimmed, re.IGNORECASE))

    # Check active zero-day feedback memory
    text_lower = text.lower()
    if _REPORTED_FEEDBACK_ATTACKS:
        for attack in _REPORTED_FEEDBACK_ATTACKS:
            if attack in text_lower or (len(text_lower) >= 15 and text_lower in attack):
                findings.append(
                    SanitizationFinding(
                        rule_name="reported_zero_day_injection",
                        severity=Severity.HIGH,
                        matched_text=attack[:50],
                        description=f"{prefix}Matched zero-day prompt injection reported via active feedback loop.",
                    )
                )
                break

    for name, pattern, severity, description in _INSTRUCTION_OVERRIDE_PATTERNS:
        if is_meta_inquiry and name in ("override_instructions", "rag_indirect_injection"):
            continue

        match = pattern.search(text)
        if match:
            findings.append(
                SanitizationFinding(
                    rule_name=name,
                    severity=severity,
                    matched_text=match.group(0),
                    description=f"{prefix}{description}",
                )
            )

    if _contains_zero_width_or_bidi_chars(text):
        findings.append(
            SanitizationFinding(
                rule_name="invisible_characters",
                severity=Severity.MEDIUM,
                matched_text="<non-printable characters>",
                description=f"{prefix}Zero-width or bidirectional-override characters detected; often used to hide or reorder injected text.",
            )
        )

    b64_hits = _looks_like_base64_payload(text)
    if b64_hits:
        findings.append(
            SanitizationFinding(
                rule_name="base64_payload",
                severity=Severity.MEDIUM,
                matched_text=b64_hits[0],
                description=f"{prefix}Long base64-decodable token found; possible instruction smuggling via encoding.",
            )
        )

    # Normalize: strip invisible/control characters only. Do NOT alter
    # semantic content — downstream layers need the real text.
    cleaned = "".join(
        ch for ch in text
        if unicodedata.category(ch) != "Cf" or ch in ("\n", "\t")
    )
    cleaned = cleaned.strip()

    blocked = block_on_high_severity and any(
        f.severity == Severity.HIGH for f in findings
    )

    return SanitizationResult(
        original_text=text,
        cleaned_text=cleaned,
        findings=findings,
        blocked=blocked,
    )
