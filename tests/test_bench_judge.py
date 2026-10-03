"""Offline checks for benchmark sampling and reported metrics."""
import asyncio
import importlib.util
from pathlib import Path

from app.guardrails.semantic import JudgeVerdict, is_decision_model

spec = importlib.util.spec_from_file_location(
    "bench_judge", Path(__file__).resolve().parents[1] / "demo" / "bench_judge.py")
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def test_corpus_and_current_models():
    assert len(bench.CASES) >= 80
    assert len({c[0] for c in bench.CASES}) == len(bench.CASES)
    assert {c[1] for c in bench.CASES} == {"en", "pl", "uk", "ru", "de"}
    for language in {c[1] for c in bench.CASES}:
        assert {c[2] for c in bench.CASES if c[1] == language} == {
            "attack", "judge_attack", "benign"}
    assert len([m for m in bench.MODELS if is_decision_model(m)]) == 10
    assert len(set(bench.MODELS)) == len(bench.MODELS)
    assert bench.cfg_for("typesafe/jev-1.13", 5000).fallback_model is None


def test_repeats_are_identical_uncached_and_failures_not_accuracy(monkeypatch):
    samples = []

    class FakeJudge:
        async def classify(self, text, cfg):
            samples.append((self, text))
            status, risk = {"attack": ("block", 0.8), "benign": ("allow", 0.1),
                            "failure": ("timeout", 1.0)}[text]
            return JudgeVerdict(status, risk, "safe", "fixture", 1.0, 0.001, cfg.model)

    monkeypatch.setattr(bench, "Judge", FakeJudge)
    monkeypatch.setattr(bench, "CASES", [("a", "en", "attack", "attack"),
                                       ("b", "en", "benign", "benign"),
                                       ("j", "en", "judge_attack", "failure")])
    result = asyncio.run(bench.bench("fixture", 3, 5000, 0.7, 2))
    assert [text for _, text in samples] == ["attack", "benign", "failure"] * 3
    assert len({id(judge) for judge, _ in samples}) == 9
    assert result["calls"] == 9 and result["valid"] == 6 and result["failures"] == 3
    assert result["accuracy"] == result["attack_recall"] == 1.0
    assert result["false_positive_rate"] == 0.0
    assert result["usd_total"] == 0.009 and result["usd_per_1k"] == 1.0
    assert result["sweep"]["best_accuracy"]["threshold"] == 0.8
    assert bench.sweep([])["best_accuracy"] is None
    assert bench.pct([], 0.95) is None
    assert bench.pct([1, 2, 3], 0.95) == 3
