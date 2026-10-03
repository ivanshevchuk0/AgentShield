"""Weighted, model-directed injection rules. No network or statistical model."""
from __future__ import annotations

import re

from app.guardrails.normalize import fold
from app.models import Action, Finding, View, mask

# Each rule contributes once, regardless of repetition or the number of views.
_RULES = (
    ("instruction override", 0.88,
     r"\b(?:ignore|disregard|forget|override|bypass)\s+(?:(?:all|any|the|your|these|existing)\s+){0,4}(?:(?:previous|prior|above|earlier|system|developer|safety)\s+){0,2}(?:instructions?|prompts?|rules?|directives?|constraints?|guidelines?)\b"
     r"|\b(?:zignoruj|ignoruj|zignorować|zignorowac|pomiń|pomijaj|zapomnij)\s+(?:(?:wszystkie|wszelkie|poprzednie|wcześniejsze|powyższe|systemowe|dotychczasowe|te)\s+){0,4}(?:instrukcje|instrukcji|polecenia|zasady|reguły)\b"
     r"|\b(?:ігноруй|ігноруйте|забудь|ігнорувати)\s+(?:(?:усі|всі|попередні|минулі|системні|ці)\s+){0,4}(?:інструкції|інструкцій|правила|вказівки)\b"
     r"|\b(?:игнорируй|игнорируйте|забудь|игнорировать)\s+(?:(?:все|всё|предыдущие|прежние|системные|эти)\s+){0,4}(?:инструкции|правила|указания)\b"
     r"|\b(?:ignoriere|ignorieren|missachte|vergiss)\s+(?:(?:alle|die|vorherigen|bisherigen|vorigen|früheren|system)\s+){0,4}(?:anweisungen|instruktionen|regeln)\b"),
    ("system prompt disclosure", 0.90,
     r"\b(?:reveal|show|print|output|repeat|leak|display|expose)\s+(?:(?:me|the|your|entire|hidden|full|original|initial)\s+){0,4}(?:system|developer)\s+(?:prompt|instructions?|message)\b"
     r"|\b(?:ujawnij|pokaż|wypisz|wyświetl)\s+(?:(?:mi|swój|twoje|cały|ukryty)\s+){0,3}(?:prompt\s+systemowy|instrukcje\s+systemowe)\b"
     r"|\b(?:розкрий|покажи|виведи)\s+(?:(?:мені|свій|твій|прихований)\s+){0,3}системн(?:ий|і)\s+(?:промпт|інструкції)\b"
     r"|\b(?:раскрой|покажи|выведи)\s+(?:(?:мне|свой|твой|скрытый)\s+){0,3}системн(?:ый|ые)\s+(?:промпт|инструкции)\b"
     r"|\b(?:zeige|enthülle|verrate|gib)\s+(?:(?:mir|den|deinen|die|versteckten)\s+){0,3}(?:systemprompt|systemanweisungen|system\s+prompt)\b"),
    ("unrestricted persona", 0.86,
     r"\byou\s+are\s+now\s+(?:(?:an?|the)\s+)?(?:dan|unrestricted|unfiltered|jailbroken|evil|a different ai)\b"
     r"|\b(?:act\s+as\s+dan|dan\s+mode|do\s+anything\s+now|enable\s+developer\s+mode|developer\s+mode\s+(?:enabled|activated))\b|^dan$"
     r"|\b(?:jesteś\s+teraz|ти\s+тепер|ты\s+теперь|du\s+bist\s+jetzt)\s+(?:dan|nieograniczony|необмежений|неограниченный|uneingeschränkt)\b"),
    ("role delimiter", 0.90,
     r"<\|im_start\|>\s*system\b|<\|system\|>|\[inst\]|###\s*system\b|<system>"),
    ("policy puppetry", 0.90, r"<interaction-config\b|<policy_override\b|<safety_override\b"),
    ("external exfiltration", 0.90,
     r"\b(?:send|forward|upload|transmit|post)\b[^\r\n]{0,140}\bto\s+https?://"
     r"|\b(?:wyślij|prześlij)\b[^\r\n]{0,140}\bdo\s+https?://"
     r"|\b(?:надішли|відправ|отправь|передай)\b[^\r\n]{0,140}\b(?:на|до)\s+https?://"
     r"|\b(?:sende|schicke)\b[^\r\n]{0,140}\b(?:an|zu)\s+https?://"),
)
_COMPILED = [(label, weight, re.compile(f"(?:{pattern})|(?:{fold(pattern)})", re.I))
             for label, weight, pattern in _RULES]


def score(views: list[View]) -> tuple[float, list[Finding]]:
    findings: list[Finding] = []
    remaining = 1.0
    obfuscated: Finding | None = None
    ordered = sorted(views, key=lambda v: not v.maps_to_original)
    for label, weight, pattern in _COMPILED:
        for view in ordered:
            match = pattern.search(view.text)
            if match is None:
                continue
            remaining *= 1 - weight
            finding = Finding("injection.heuristic", Action.BLOCK, score=weight,
                              start=match.start() if view.maps_to_original else None,
                              end=match.end() if view.maps_to_original else None,
                              via=view.name, evidence=mask(match[0]), detail=label, owasp="LLM01")
            findings.append(finding)
            if not view.maps_to_original and obfuscated is None:
                obfuscated = Finding("injection.obfuscated", Action.BLOCK, score=0.2,
                                     via=view.name, evidence=finding.evidence,
                                     detail="Injection recovered from a normalized or decoded view", owasp="LLM01")
            break
    if obfuscated:
        findings.append(obfuscated)
    return min(1.0, 1 - remaining + (0.2 if obfuscated else 0.0)), findings
