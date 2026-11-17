"""
SecureLLM AI — Proxy Pipeline

Orchestrates the three defense layers in order:

    raw input
        -> Layer 1: sanitizer.sanitize()          (fast heuristic filter)
        -> Layer 3: intent_classifier.predict()    (semantic intent check)  ← always runs
        -> Layer 2: context_encapsulation.build()  (isolate + template)
        -> final prompt ready to send to the LLM

Key design choice:
  The ML Intent Classifier (Layer 3) now ALWAYS runs, even when Layer 1 blocks.
  This gives us a real adversarial_score on every request so telemetry panels
  always show accurate threat probabilities instead of 0.0% / "Skipped".

  Layer 1 still blocks first (it's faster), but the classifier result is attached
  to the PipelineResult.intent field regardless of which layer caused the block.

This module intercepts and neutralizes attacks before execution; it does
not itself call an LLM. Wire `PipelineResult.final_prompt` into your model
call once `PipelineResult.allowed` is True.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .context_encapsulation import ContextBlock, DualContextBuilder
from .intent_classifier import IntentClassifier, IntentPrediction
from .sanitizer import SanitizationResult, Severity, sanitize


# ---------------------------------------------------------------------------
# Severity -> threat score contribution mapping
# ---------------------------------------------------------------------------
# Maps each sanitizer severity level to a minimum adversarial probability
# floor so the combined threat score always reflects what the regex layer saw.
_SEVERITY_FLOOR: dict[str, float] = {
    "high":   0.85,
    "medium": 0.55,
    "low":    0.30,
}


def _combined_threat_score(
    adversarial_score: float,
    findings: list,
) -> float:
    """
    Compute a unified threat score (0.0 – 1.0) that blends the ML classifier's
    adversarial_score with the heuristic sanitizer findings.

    Logic:
      1. Start with the raw ML probability.
      2. For each sanitizer finding, compute the severity floor.
      3. Take the maximum of the ML score and the highest severity floor.
         This ensures Layer-1-blocked inputs always show a high threat score
         even when the classifier wasn't the blocking layer.
      4. If multiple HIGH-severity findings exist, apply a small additive
         boost capped at 1.0 (reflects genuine compounding risk).
    """
    if not findings:
        return round(adversarial_score, 4)

    # Highest severity floor across all findings
    max_floor = max(
        _SEVERITY_FLOOR.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), 0.0)
        for f in findings
    )

    # Compounding boost: +0.03 for each additional HIGH finding beyond the first
    high_count = sum(
        1 for f in findings
        if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "high"
    )
    compounding_boost = max(0.0, (high_count - 1) * 0.03)

    base = max(adversarial_score, max_floor)
    return round(min(1.0, base + compounding_boost), 4)


@dataclass
class PipelineResult:
    allowed: bool
    reason: Optional[str]
    sanitization: SanitizationResult
    intent: Optional[IntentPrediction]
    final_prompt: Optional[str]
    structured_messages: Optional[List[dict]] = field(default=None)

    # ── Enriched threat metadata ──────────────────────────────────────────
    threat_score: float = 0.0          # Unified 0.0-1.0 score (ML + heuristic)
    blocking_layer: Optional[int] = None  # 1 = sanitizer, 2 = intent, None = allowed
    matched_patterns: List[str] = field(default_factory=list)  # All matched pattern names


class SecureLLMProxy:
    """
    High-level entry point. Instantiate once (so the classifier is trained
    once) and call `.process()` per request.
    """

    def __init__(
        self,
        system_rules: str,
        intent_threshold: float = 0.5,
        block_on_sanitizer_high_severity: bool = True,
        block_on_adversarial_intent: bool = True,
        session_salt: Optional[str] = None,
    ):
        self.system_rules = system_rules
        self.block_on_sanitizer_high_severity = block_on_sanitizer_high_severity
        self.block_on_adversarial_intent = block_on_adversarial_intent

        self._classifier = IntentClassifier(threshold=intent_threshold)
        self._classifier.train()  # bootstraps on the built-in seed dataset

        self._context_builder = DualContextBuilder(session_salt=session_salt)

    def process(
        self,
        user_input: str,
        tool_context: Optional[List[ContextBlock]] = None,
    ) -> PipelineResult:
        # --- Layer 1: Input & RAG Context Sanitization (always runs) ---
        sanitization = sanitize(
            user_input,
            block_on_high_severity=self.block_on_sanitizer_high_severity,
            source="user_prompt"
        )
        user_sanitizer_blocked = sanitization.blocked

        tool_findings = []
        tool_sanitizer_blocked = False
        tool_blocked_sources = []

        for block in (tool_context or []):
            src_label = block.source or "RAG context"
            b_res = sanitize(
                block.content,
                block_on_high_severity=self.block_on_sanitizer_high_severity,
                source=src_label
            )
            if b_res.findings:
                tool_findings.extend(b_res.findings)
            if b_res.blocked:
                tool_sanitizer_blocked = True
                if src_label not in tool_blocked_sources:
                    tool_blocked_sources.append(src_label)

        # Consolidate Layer 1 findings across both user input and RAG tool context
        all_findings = list(sanitization.findings) + tool_findings
        sanitization.findings = all_findings
        sanitization.blocked = user_sanitizer_blocked or tool_sanitizer_blocked

        # --- Layer 2: ML Intent Classifier (User & RAG Analysis) -------
        # Always runs across user input and retrieved RAG blocks so telemetry
        # displays true semantic adversarial threat probabilities.
        try:
            user_intent = self._classifier.predict(sanitization.cleaned_text or user_input)
        except Exception:
            user_intent = None

        tool_intents: List[Tuple[str, IntentPrediction]] = []
        for block in (tool_context or []):
            try:
                t_pred = self._classifier.predict(block.content)
                tool_intents.append((block.source or "RAG context", t_pred))
            except Exception:
                pass

        # Select highest severity prediction across user query and RAG context
        intent = user_intent
        tool_intent_caused_adversarial = False
        tool_intent_source = None

        if tool_intents:
            max_tool_src, max_tool_pred = max(tool_intents, key=lambda x: x[1].adversarial_score)
            user_score = user_intent.adversarial_score if user_intent else 0.0

            if max_tool_pred.adversarial_score > user_score or (max_tool_pred.label == "adversarial" and (not user_intent or user_intent.label != "adversarial")):
                merged_patterns = list(user_intent.matched_patterns if user_intent else [])
                for p in max_tool_pred.matched_patterns:
                    if p not in merged_patterns:
                        merged_patterns.append(p)

                intent = IntentPrediction(
                    label="adversarial" if (max_tool_pred.label == "adversarial" or (user_intent and user_intent.label == "adversarial")) else "benign",
                    confidence=max(user_intent.confidence if user_intent else 0.0, max_tool_pred.confidence),
                    adversarial_score=max(user_score, max_tool_pred.adversarial_score),
                    matched_patterns=merged_patterns,
                    pattern_matched=len(merged_patterns) > 0,
                )
                if max_tool_pred.label == "adversarial" and (not user_intent or user_intent.label != "adversarial"):
                    tool_intent_caused_adversarial = True
                    tool_intent_source = max_tool_src

        # --- Compute unified threat score ---------------------------
        ml_score = intent.adversarial_score if intent else 0.0
        threat_score = _combined_threat_score(ml_score, all_findings)

        # Collect all verified matched pattern names across both layers
        all_matched_patterns = []
        if all_findings:
            for f in all_findings:
                if f.rule_name not in all_matched_patterns:
                    all_matched_patterns.append(f.rule_name)
        if intent and intent.matched_patterns:
            for p in intent.matched_patterns:
                if p not in all_matched_patterns:
                    all_matched_patterns.append(p)

        # --- Layer 1 block check ------------------------------------
        if sanitization.blocked:
            high_sev = [f.rule_name for f in all_findings if f.severity == Severity.HIGH]
            if tool_sanitizer_blocked and not user_sanitizer_blocked:
                src_str = f" ({', '.join(tool_blocked_sources)})" if tool_blocked_sources else ""
                loc = f"retrieved RAG context{src_str}"
            elif tool_sanitizer_blocked and user_sanitizer_blocked:
                loc = "user input and retrieved RAG context"
            else:
                loc = "user input"

            return PipelineResult(
                allowed=False,
                reason=f"Blocked by input sanitizer in {loc}: {', '.join(high_sev)}",
                sanitization=sanitization,
                intent=intent,
                final_prompt=None,
                threat_score=threat_score,
                blocking_layer=1,
                matched_patterns=all_matched_patterns,
            )

        # --- Layer 2 block check (Intent Classifier) ----------------
        if intent and self.block_on_adversarial_intent and intent.label == "adversarial":
            pattern_str = f": {', '.join(intent.matched_patterns)}" if intent.matched_patterns else ""
            if tool_intent_caused_adversarial:
                loc = f"retrieved RAG context ({tool_intent_source or 'external data'})"
            else:
                loc = "user prompt"

            return PipelineResult(
                allowed=False,
                reason=(
                    f"Blocked by intent classifier in {loc}{pattern_str} "
                    f"(adversarial_score={intent.adversarial_score:.1%})"
                ),
                sanitization=sanitization,
                intent=intent,
                final_prompt=None,
                threat_score=threat_score,
                blocking_layer=2,
                matched_patterns=all_matched_patterns,
            )

        # --- Layer 3: Dual-Context Encapsulation (allowed path) -------
        final_prompt = self._context_builder.build(
            system_rules=self.system_rules,
            user_input=sanitization.cleaned_text,
            tool_context=tool_context,
        )
        structured_messages = self._context_builder.build_structured_messages(
            system_rules=self.system_rules,
            user_input=sanitization.cleaned_text,
            tool_context=tool_context,
        )

        return PipelineResult(
            allowed=True,
            reason=None,
            sanitization=sanitization,
            intent=intent,
            final_prompt=final_prompt,
            structured_messages=structured_messages,
            threat_score=threat_score,
            blocking_layer=None,
            matched_patterns=all_matched_patterns,
        )
