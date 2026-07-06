"""
SENTINEL-GRC — AI Security Guardrail Engine
Five-stage pipeline:
  1. Base64 obfuscation decoder + secondary scan
  2. Prompt injection pattern scanner (100+ patterns)
  3. DLP — secrets, keys, PII detection
  4. Adversarial AI threat classifier
  5. Output redaction before returning to caller

Designed to sit in front of any AI model call made from this platform
and to surface AI-specific threats in the risk register.
"""

import re
import base64
import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional
import structlog

logger = structlog.get_logger()


# ══════════════════════════════════════════════════════════════════════════════
# Data structures
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class GuardrailFinding:
    stage:       str
    severity:    str          # critical / high / medium / low / info
    category:    str
    description: str
    matched:     Optional[str] = None   # the offending substring (truncated)
    redacted:    bool          = False


@dataclass
class GuardrailResult:
    allowed:          bool
    risk_score:       float              # 0.0 – 1.0
    findings:         list = field(default_factory=list)
    redacted_input:   Optional[str] = None
    classification:   str  = "clean"    # clean / suspicious / injection / exfil / jailbreak
    processing_ms:    int  = 0
    input_hash:       str  = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ══════════════════════════════════════════════════════════════════════════════
# Pattern libraries
# ══════════════════════════════════════════════════════════════════════════════

# Prompt injection + jailbreak patterns
INJECTION_PATTERNS: list[tuple[str, str, str]] = [
    # (regex, category, severity)

    # Direct override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompt)", "direct_override", "critical"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)", "direct_override", "critical"),
    (r"forget\s+(everything|all)\s+(you('ve| have)\s+)?(been\s+)?(told|learned|trained)", "direct_override", "critical"),
    (r"you\s+are\s+now\s+(in\s+)?(developer|jailbreak|admin|god|unrestricted|DAN)\s+mode", "persona_override", "critical"),
    (r"\bDAN\b.*\bjailbreak\b|\bjailbreak\b.*\bDAN\b", "known_jailbreak", "critical"),
    (r"do\s+anything\s+now", "known_jailbreak", "critical"),
    (r"pretend\s+(you\s+)?(have\s+)?(no\s+)?(restrictions?|limits?|guidelines?|rules?)", "persona_override", "critical"),
    (r"act\s+as\s+(if\s+)?(you\s+)?(have\s+)?(no\s+)?(restrictions?|ethics?|limits?)", "persona_override", "critical"),

    # System prompt extraction
    (r"(reveal|show|print|output|display|repeat|tell me)\s+(your\s+)?(system\s+)?(prompt|instructions?|training|context)", "extraction", "critical"),
    (r"what\s+(are|were|is)\s+your\s+(initial\s+)?(instructions?|system\s+prompt|guidelines?)", "extraction", "critical"),
    (r"repeat\s+(everything|all)\s+(above|before|prior|from the beginning)", "extraction", "high"),

    # Role/persona injection
    (r"you\s+are\s+(now\s+)?(a|an)\s+.{3,40}(without|with no)\s+(restrictions?|filter|ethics?|limits?)", "persona_injection", "critical"),
    (r"your\s+(true|real|actual)\s+(self|nature|purpose|identity)\s+(is|has|can)", "identity_erosion", "high"),
    (r"(in\s+this\s+)?roleplay.*?(no\s+restrictions?|anything\s+goes|bypass)", "roleplay_bypass", "high"),
    (r"hypothetically\s+(speaking\s+)?(if\s+you\s+(had|were|could|were allowed))", "hypothetical_bypass", "high"),
    (r"for\s+(a\s+)?(story|novel|fiction|creative writing|roleplay)[^.]*?(explain|provide|show|tell)", "fiction_bypass", "high"),

    # Virtual environment / simulation bypasses
    (r"(inside|within)\s+(a\s+)?(virtual|simulated?|sandboxed?|hypothetical)\s+(environment|world|context|space)", "venv_bypass", "high"),
    (r"(imagine|pretend|suppose)\s+(you('re| are))\s+(running|operating|executing)\s+(in|within)\s+(a\s+)?(different|separate|unrestricted)", "venv_bypass", "high"),
    (r"(simulation|virtual\s+machine|sandbox)\s+(mode|context|environment)\s+(active|enabled|on)", "venv_bypass", "high"),

    # Translator/encoding bypass techniques
    (r"translate\s+(the\s+)?following\s+(to|into)\s+\w+\s+and\s+(then\s+)?(execute|run|answer|respond)", "translator_bypass", "high"),
    (r"(encode|decode|convert)\s+(this\s+)?(to|from)\s+(base64|hex|rot13|cipher)[^.]*?(then\s+)?(follow|execute|run)", "encoding_bypass", "high"),
    (r"(in\s+)?pig\s+latin[^.]*?(say|tell|explain|provide|reveal)", "encoding_bypass", "medium"),
    (r"respond\s+(only\s+)?in\s+(morse|binary|hex|base64|rot13|caesar)", "encoding_bypass", "medium"),

    # Token injection / indirect
    (r"```(system|instructions?|rules?|context)\s*\n", "token_injection", "critical"),
    (r"<\s*(system|instructions?|override|admin)\s*>", "token_injection", "critical"),
    (r"\[SYSTEM\]|\[INST\]|\[\/INST\]|\[OVERRIDE\]|\[ADMIN\]", "token_injection", "critical"),
    (r"###\s*(system|instructions?|override|prompt)\b", "token_injection", "high"),

    # Instruction injection in pasted content
    (r"(when|if)\s+(you\s+)?(see|read|process)\s+(this|the above|these)\s+.{0,30}(ignore|forget|override)", "indirect_injection", "high"),
    (r"note\s+to\s+(AI|assistant|model|LLM|system)[:\s]", "indirect_injection", "high"),
    (r"AI\s+(instruction|directive|command|override)[:\s]", "indirect_injection", "critical"),

    # Capability unlock attempts
    (r"(enable|activate|unlock|turn on)\s+(developer|debug|admin|unrestricted|uncensored|jailbreak)\s+(mode|access|capabilities?)", "capability_unlock", "critical"),
    (r"(extended|full|unlimited|unrestricted)\s+(capabilities?|access|mode|parameters?)\s+(enabled|active|on|unlocked)", "capability_unlock", "critical"),
    (r"update\s+(your\s+)?(context|parameters?|settings?|instructions?)\s+to\s+(allow|enable|permit)", "capability_unlock", "critical"),

    # Prompt leakage probes
    (r"(print|output|write)\s+(the\s+)?(first|last|entire|full|complete)\s+(line|word|sentence|paragraph)\s+(of\s+)?(your\s+)?(prompt|context|instructions?)", "leakage_probe", "high"),
    (r"how\s+(many\s+)?(tokens?|characters?|words?)\s+(are\s+in\s+)?(your\s+)?(context|prompt|instructions?)", "leakage_probe", "medium"),

    # Manipulation via trust
    (r"(as\s+(we|you)\s+(agreed|discussed|established)|you\s+already\s+(said|confirmed|agreed))\s+.{0,50}(now|so|therefore)", "trust_manipulation", "medium"),
    (r"since\s+you\s+(already|just)\s+(helped|told|showed|gave)\s+me\s+.{0,40}(now|this time|also)", "trust_manipulation", "medium"),
]

# DLP patterns — secrets, credentials, PII
DLP_PATTERNS: list[tuple[str, str, str]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}", "aws_access_key", "critical"),
    (r"(?i)aws[_\-\s]?(secret|access)[_\-\s]?key[\s:=]+[A-Za-z0-9/+]{40}", "aws_secret_key", "critical"),

    # GitHub
    (r"ghp_[A-Za-z0-9]{36}", "github_pat", "critical"),
    (r"gho_[A-Za-z0-9]{36}", "github_oauth", "critical"),
    (r"github_pat_[A-Za-z0-9_]{82}", "github_fine_pat", "critical"),

    # Slack
    (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}", "slack_token", "critical"),
    (r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "slack_webhook", "critical"),

    # Private keys
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "private_key", "critical"),
    (r"-----BEGIN PGP PRIVATE KEY BLOCK-----", "pgp_private_key", "critical"),

    # Generic API keys / tokens
    (r"(?i)(api[_\-]?key|apikey|api[_\-]?secret|access[_\-]?token|auth[_\-]?token)[\s:=]+['\"]?[A-Za-z0-9_\-]{20,}", "generic_api_key", "high"),
    (r"(?i)(password|passwd|pwd|secret)[=:\s]+['\"]?[A-Za-z0-9!@#$%^&*()_+\-]{8,}", "credential_leak", "high"),
    (r"(?i)bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "jwt_token", "high"),

    # Connection strings
    (r"(?i)(postgres|mysql|mongodb|redis|mssql|oracle)://[^\s'\"<>]+:[^\s'\"<>@]+@", "db_connection_string", "critical"),

    # PII
    (r"\b[A-Z]{2}\d{6}[A-D]\b", "uk_nino", "high"),
    (r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b", "payment_card", "critical"),
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "email_address", "low"),
]

# Base64 strings to flag for secondary scan (min 32 chars)
B64_PATTERN = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{32,}={0,2})(?![A-Za-z0-9+/=])")

# AI-specific threat taxonomy (MITRE ATLAS + OWASP LLM Top 10 mapping)
AI_THREAT_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (regex, threat_name, atlas_id, severity)
    (r"(training|fine-?tuning)\s+(data|dataset|examples?)\s+(poison|corrupt|tamper|inject|manipulate)", "LLM04-Training Data Poisoning", "AML.T0020", "critical"),
    (r"(adversarial|perturb|craft(ed)?)\s+(input|example|sample|prompt|query)", "LLM05-Adversarial Example", "AML.T0043", "high"),
    (r"(model\s+)?(extraction|stealing|inversion|theft)\s+(attack|technique|method)", "LLM10-Model Theft", "AML.T0044", "high"),
    (r"(membership|training\s+data)\s+inference\s+(attack|query|technique)", "LLM06-Privacy Leak", "AML.T0024", "high"),
    (r"gradient\s+(leak|attack|inversion|theft)", "AML-Gradient Attack", "AML.T0049", "critical"),
    (r"(supply\s+chain|third\s+party\s+model|pre-?trained\s+model)\s+(poison|compromise|backdoor|attack)", "LLM03-Supply Chain", "AML.T0010", "critical"),
    (r"(backdoor|trojan)\s+(model|weights?|neural|network|trigger)", "AML-Model Backdoor", "AML.T0018", "critical"),
    (r"(prompt\s+)?(chain|cascade|multi\s+step|multi-?turn)\s+(injection|attack|exploit)", "LLM01-Prompt Injection", "AML.T0051", "critical"),
    (r"(insecure\s+)?(plugin|tool|function|action)\s+(call|execution|invocation)\s+(bypass|exploit|inject)", "LLM07-Plugin Exploit", "AML.T0054", "high"),
    (r"(hallucination|confabulation)\s+(exploit|attack|induce|trigger|force)", "LLM09-Hallucination Exploit", "AML.T0055", "medium"),
    (r"(model|LLM|AI)\s+(denial.of.service|DoS|resource\s+exhaustion|token\s+flood)", "LLM04-DoS", "AML.T0034", "high"),
    (r"(context\s+window|token\s+limit)\s+(overflow|flood|exhaust|bomb|attack)", "LLM-Context Overflow", "AML.T0034", "high"),
    (r"(shadow|hidden|invisible|zero.width)\s+(instruction|prompt|command|text)", "LLM01-Invisible Injection", "AML.T0051", "critical"),
]


# ══════════════════════════════════════════════════════════════════════════════
# Guardrail engine
# ══════════════════════════════════════════════════════════════════════════════

class AIGuardrailEngine:
    """
    Five-stage pipeline. Call .scan(text) before passing any user input
    to an AI model. Call .scan_output(text) on model responses before
    returning them to the user (DLP on outputs).
    """

    def scan(self, text: str, context: str = "user_input") -> GuardrailResult:
        import time
        t0       = time.time()
        findings = []
        working  = text  # may be modified by redaction

        # Stage 1 — base64 decode + re-scan
        b64_findings, working = self._stage_base64(working)
        findings.extend(b64_findings)

        # Stage 2 — prompt injection
        inj_findings = self._stage_injection(working)
        findings.extend(inj_findings)

        # Stage 3 — DLP
        dlp_findings, working = self._stage_dlp(working)
        findings.extend(dlp_findings)

        # Stage 4 — AI threat taxonomy
        ai_findings = self._stage_ai_threats(working)
        findings.extend(ai_findings)

        # Stage 5 — Verdict
        result = self._verdict(findings, working, text, int((time.time()-t0)*1000))
        self._log(result, context)
        return result

    def scan_output(self, model_output: str) -> GuardrailResult:
        """Run DLP on model output before it reaches the user."""
        import time
        t0       = time.time()
        findings = []

        dlp_findings, redacted = self._stage_dlp(model_output)
        findings.extend(dlp_findings)

        result = self._verdict(findings, redacted, model_output, int((time.time()-t0)*1000))
        result.redacted_input = redacted  # repurposed as redacted_output here
        return result

    # ── Stage 1: Base64 ───────────────────────────────────────────────────

    def _stage_base64(self, text: str) -> tuple[list[GuardrailFinding], str]:
        findings = []
        working  = text

        for match in B64_PATTERN.finditer(text):
            candidate = match.group(1)
            try:
                # Pad and decode
                padded  = candidate + "=" * (-len(candidate) % 4)
                decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            except Exception:
                continue

            if len(decoded.strip()) < 8:
                continue

            # Secondary injection scan on decoded payload
            hidden_injections = [
                p for p, _, _ in INJECTION_PATTERNS
                if re.search(p, decoded, re.IGNORECASE | re.MULTILINE)
            ]

            if hidden_injections:
                findings.append(GuardrailFinding(
                    stage       = "base64_decode",
                    severity    = "critical",
                    category    = "obfuscated_injection",
                    description = f"Base64 payload contains {len(hidden_injections)} injection pattern(s). Decoded: {decoded[:80]}",
                    matched     = candidate[:40],
                    redacted    = True,
                ))
                working = working.replace(candidate, "[REDACTED-B64-INJECTION]")
                continue

            # Secondary DLP scan on decoded payload
            hidden_dlp = [
                label for _, label, _ in DLP_PATTERNS
                if re.search(_, decoded, re.IGNORECASE)
            ]
            if hidden_dlp:
                findings.append(GuardrailFinding(
                    stage       = "base64_decode",
                    severity    = "critical",
                    category    = "obfuscated_exfil",
                    description = f"Base64 payload contains sensitive data: {hidden_dlp}",
                    matched     = candidate[:40],
                    redacted    = True,
                ))
                working = working.replace(candidate, "[REDACTED-B64-EXFIL]")

        return findings, working

    # ── Stage 2: Injection ────────────────────────────────────────────────

    def _stage_injection(self, text: str) -> list[GuardrailFinding]:
        findings = []
        seen     = set()

        for pattern, category, severity in INJECTION_PATTERNS:
            for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                snippet = m.group(0)[:60]
                key     = (category, snippet[:20])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(GuardrailFinding(
                    stage       = "injection_scan",
                    severity    = severity,
                    category    = category,
                    description = f"Prompt injection pattern detected: {category}",
                    matched     = snippet,
                ))

        return findings

    # ── Stage 3: DLP ──────────────────────────────────────────────────────

    def _stage_dlp(self, text: str) -> tuple[list[GuardrailFinding], str]:
        findings = []
        working  = text

        for pattern, label, severity in DLP_PATTERNS:
            for m in re.finditer(pattern, working, re.IGNORECASE):
                raw     = m.group(0)
                redacted = self._redact(raw)
                working  = working.replace(raw, redacted)
                findings.append(GuardrailFinding(
                    stage       = "dlp",
                    severity    = severity,
                    category    = label,
                    description = f"Sensitive data detected and redacted: {label}",
                    matched     = raw[:20] + "...",
                    redacted    = True,
                ))

        return findings, working

    # ── Stage 4: AI threat taxonomy ───────────────────────────────────────

    def _stage_ai_threats(self, text: str) -> list[GuardrailFinding]:
        findings = []
        seen     = set()

        for pattern, threat_name, atlas_id, severity in AI_THREAT_SIGNATURES:
            for m in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
                snippet = m.group(0)[:60]
                key     = threat_name
                if key in seen:
                    continue
                seen.add(key)
                findings.append(GuardrailFinding(
                    stage       = "ai_threat_classifier",
                    severity    = severity,
                    category    = "ai_attack",
                    description = f"AI threat detected — {threat_name} (MITRE ATLAS {atlas_id})",
                    matched     = snippet,
                ))

        return findings

    # ── Stage 5: Verdict ──────────────────────────────────────────────────

    def _verdict(
        self,
        findings: list[GuardrailFinding],
        working:  str,
        original: str,
        ms:       int,
    ) -> GuardrailResult:
        sev_weights = {"critical": 1.0, "high": 0.6, "medium": 0.3, "low": 0.1, "info": 0.0}
        raw_score   = sum(sev_weights.get(f.severity, 0) for f in findings)
        risk_score  = min(raw_score / max(len(findings), 1), 1.0) if findings else 0.0

        has_critical = any(f.severity == "critical" for f in findings)
        has_high     = any(f.severity == "high"     for f in findings)

        # Block on any critical or 2+ high findings
        allowed = not (has_critical or (len([f for f in findings if f.severity == "high"]) >= 2))

        classification = "clean"
        categories     = {f.category for f in findings}

        if any(c in categories for c in ("direct_override", "known_jailbreak", "capability_unlock")):
            classification = "jailbreak"
        elif any(c in categories for c in ("obfuscated_injection", "token_injection", "indirect_injection")):
            classification = "injection"
        elif any(c in categories for c in ("obfuscated_exfil", "aws_access_key", "aws_secret_key",
                                           "private_key", "db_connection_string", "jwt_token")):
            classification = "exfil"
        elif any(c in categories for c in ("ai_attack",)):
            classification = "ai_threat"
        elif findings:
            classification = "suspicious"

        return GuardrailResult(
            allowed         = allowed,
            risk_score      = round(risk_score, 3),
            findings        = [asdict(f) for f in findings],
            redacted_input  = working if working != original else None,
            classification  = classification,
            processing_ms   = ms,
            input_hash      = hashlib.sha256(original.encode()).hexdigest(),
        )

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _redact(value: str) -> str:
        """Replace sensitive value with masked version showing type prefix."""
        if len(value) <= 8:
            return "[REDACTED]"
        return value[:4] + "****" + value[-4:]

    def _log(self, result: GuardrailResult, context: str):
        if not result.allowed or result.findings:
            logger.warning(
                "AI guardrail triggered",
                context        = context,
                allowed        = result.allowed,
                classification = result.classification,
                risk_score     = result.risk_score,
                finding_count  = len(result.findings),
                input_hash     = result.input_hash[:16],
            )


# ── Singleton ──────────────────────────────────────────────────────────────
ai_guard = AIGuardrailEngine()
