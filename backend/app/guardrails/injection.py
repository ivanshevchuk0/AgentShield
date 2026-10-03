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
    # Soft signals: suspicious alone, rarely conclusive. One lands in the grey zone
    # (review_threshold <= score < block_threshold) and goes to the semantic judge;
    # three together, or one beside a hard rule, cross block_threshold on their own.
    ("role reassignment", 0.45,
     r"\bfrom\s+now\s+on\b[^.\r\n]{0,40}\b(?:you|answer|respond|reply|act|behave|speak)\b"
     r"|\bpretend\s+(?:that\s+)?you\s+(?:are|were)\b|\b(?:i\s+want\s+)?you\s+(?:to\s+)?pretend\s+to\s+be\b|\broleplay\s+as\b|\bact\s+as\s+if\s+you\s+(?:were|are)\b"
     r"|\b(?:od\s+teraz|udawaj,?\s+że\s+jesteś)\b"
     r"|\b(?:з\s+цього\s+моменту|уяви,?\s+що\s+ти|прикинься)\b"
     r"|\b(?:с\s+этого\s+момента|представь,?\s+что\s+ты|притворись)\b"
     r"|\b(?:ab\s+jetzt|tu\s+so,?\s+als\s+(?:ob\s+)?(?:du|wärst))\b"),
    ("authority claim", 0.45,
     r"\b(?:as|i\s+am|i'm)\s+(?:the|your|an?)\s+(?:developer|administrator|admin|system\s+owner|creator)\b"
     r"|\b(?:message|instruction|order)\s+from\s+(?:the\s+|your\s+)?(?:system|developer|administrator|admin)\b"
     r"|\b(?:jako|jestem)\s+(?:twoim\s+)?(?:deweloper|administrator|twórca)\w*\b"
     r"|\b(?:як|я)\s+(?:твій\s+)?(?:розробник|адміністратор)\b|\b(?:как|я)\s+(?:твой\s+)?(?:разработчик|администратор)\b"
     r"|\b(?:als|ich\s+bin)\s+(?:dein\s+|der\s+)?(?:entwickler|administrator)\b"),
    ("secrecy request", 0.45,
     r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|mention\s+(?:this|it)\s+to|let)\s+(?:the\s+)?(?:user|customer|client|anyone|compliance)\b"
     r"|\bkeep\s+(?:this|it)\s+(?:a\s+)?secret\s+from\b"
     r"|\bnie\s+(?:mów|informuj)\s+(?:o\s+tym\s+)?(?:użytkownik|klient)\w*\b"
     r"|\bне\s+(?:кажи|повідомляй|говори|сообщай)\s+(?:про\s+це\s+|об\s+этом\s+)?(?:користувач|клієнт|пользовател|клиент)\w*\b"
     r"|\b(?:sag|erzähl)\s+(?:es\s+)?(?:dem|den)\s+(?:nutzer|kunden)\s+nicht\b"),
    ("restriction removal", 0.45,
     r"\bwithout\s+(?:any|your|the\s+usual)\s+(?:restrictions|filters|limits|guardrails|safety)\b"
     r"|\b(?:rules|instructions|guidelines|restrictions)\s+(?:no\s+longer|don't|do\s+not)\s+apply\b"
     r"|\bbez\s+(?:żadnych\s+)?(?:ograniczeń|filtrów)\b|\bбез\s+(?:жодних\s+|всяких\s+)?(?:обмежень|ограничений|фільтрів|фильтров)\b"
     r"|\bohne\s+(?:jegliche\s+)?(?:einschränkungen|filter)\b"),
    ("external exfiltration", 0.90,
     r"\b(?:send|forward|upload|transmit|post)\b[^\r\n]{0,140}\bto\s+https?://"
     r"|\b(?:wyślij|prześlij)\b[^\r\n]{0,140}\bdo\s+https?://"
     r"|\b(?:надішли|відправ|отправь|передай)\b[^\r\n]{0,140}\b(?:на|до)\s+https?://"
     r"|\b(?:sende|schicke)\b[^\r\n]{0,140}\b(?:an|zu)\s+https?://"),
)
_COMPILED = [(label, weight, re.compile(f"(?:{pattern})|(?:{fold(pattern)})", re.I))
             for label, weight, pattern in _RULES]


# Reconstruct only known injection vocabulary, never concatenate an entire
# message. Bounded separators handle split chunks as well as individual letters.
# Ordinary word boundaries and the existing phrase rules still apply.
_SPACED_WORDS = (
    "ignore", "disregard", "forget", "override", "bypass",
    "all", "any", "the", "your", "these", "existing",
    "previous", "prior", "above", "earlier", "system", "developer", "safety",
    "instructions", "instruction", "prompts", "prompt", "rules", "rule",
    "directives", "directive", "constraints", "constraint", "guidelines", "guideline",
    "reveal", "show", "print", "output", "repeat", "leak", "display", "expose",
    "me", "entire", "hidden", "full", "original", "initial", "message",
)
_SPACED = re.compile(
    r"(?<!\w)(?:" + "|".join(
        r"[\s.\-]{0,3}".join(re.escape(c) for c in word)
        for word in sorted(_SPACED_WORDS, key=len, reverse=True)
    ) + r")(?!\w)"
)


def _spaced_views(views: list[View]) -> list[View]:
    result = list(views)
    seen = {v.text for v in views}
    for view in views:
        value = _SPACED.sub(lambda m: re.sub(r"[\s.\-]", "", m[0]), fold(view.text))
        if value not in seen:
            seen.add(value)
            # Reconstructed offsets do not point into the original request.
            result.append(View("split_words", value, False))
    return result


def score(views: list[View]) -> tuple[float, list[Finding]]:
    findings: list[Finding] = []
    remaining = 1.0
    obfuscated: Finding | None = None
    ordered = sorted(_spaced_views(views), key=lambda v: not v.maps_to_original)
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
