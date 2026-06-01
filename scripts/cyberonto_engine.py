#!/usr/bin/env python3
"""
cyberonto_engine.py
===================
Core CyberOnto classification engine with all methods.

Usage:
    from cyberonto_engine import RuleBasedEngine, KeywordClassifier, \
         FastTextStyleClassifier, TfidfLogisticClassifier, \
         evaluate_classifier, print_classification_report
"""

import json
import random
import re
import math
import time
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional

import numpy as np

# ─── Severity ordering ───
SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_IDX = {s: i for i, s in enumerate(SEVERITIES)}

# ─── Keyword dictionaries ───
KEYWORDS = {
    "Critical": [
        "remote code execution", "rce", "arbitrary code execution", "command injection",
        "sql injection", "authentication bypass", "unauthenticated", "heap buffer overflow",
        "use-after-free", "deserialization", "zero-day", "actively exploited",
        "privilege escalation", "root access", "system compromise", "backdoor",
        "remote exploitation", "critical", "wormable", "pre-auth", "pre-authentication",
        "unauthorized access", "full compromise", "code execution", "sandbox escape",
        "kernel exploit", "elevation of privilege", "lpe", "security feature bypass",
    ],
    "High": [
        "buffer overflow", "cross-site scripting", "xss", "information disclosure",
        "denial of service", "dos", "path traversal", "directory traversal",
        "xml external entity", "xxe", "server-side request forgery", "ssrf",
        "cross-site request forgery", "csrf", "cryptographic weakness", "weak encryption",
        "missing authentication", "broken access control", "insecure deserialization",
        "sensitive data exposure", "insufficient logging", "security misconfiguration",
        "using components with known vulnerabilities", "insufficiently protected credentials",
        "open redirect", "clickjacking", "race condition", "integer overflow",
        "format string", "memory corruption", "double free", "out of bounds",
    ],
    "Medium": [
        "reflected xss", "information leak", "verbose error", "verbose logging",
        "clickjacking", "missing hsts", "missing csp", "weak cipher",
        "session fixation", "insecure cookie", "missing rate limiting",
        "password autocomplete", "insecure default", "missing httponly",
        "missing secure flag", "ssl stripping", "mixed content",
        "cache poisoning", "http request smuggling", "insecure file permissions",
        "improper input validation", "missing authorization check",
        "timing attack", "side channel", "information exposure",
    ],
    "Low": [
        "version disclosure", "fingerprinting", "banner grabbing",
        "missing security headers", "cookie without samesite",
        "documentation issue", "informational", "best practice",
        "recommended configuration", "defense in depth",
        "missing x-frame-options", "missing x-content-type-options",
        "referrer policy", "feature policy", "permissions policy",
    ],
}

# Base keyword weights
BASE_WEIGHTS = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0}


# ─── Pre-defined n-gram patterns (FastText-style, NOT Facebook FastText) ───
NGRAM_PATTERNS = [
    "remote code", "code execution", "sql injection", "buffer overflow",
    "cross-site", "authentication bypass", "information disclosure",
    "denial of service", "privilege escalation", "path traversal",
    "command injection", "deserialization", "use-after-free",
    "heap overflow", "format string", "integer overflow",
    "race condition", "memory corruption", "double free",
    "xml external", "server-side request", "cross-site request",
    "open redirect", "security misconfiguration", "sensitive data",
    "cryptographic weakness", "insecure deserialization",
]


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z]+", text.lower())


def _contains(text: str, pattern: str) -> bool:
    return pattern in text.lower()


# ═══════════════════════════════════════════════════════════
# Rule-Based Engine (Two-Tier)
# ═══════════════════════════════════════════════════════════
class RuleBasedEngine:
    """Two-tier deterministic triage engine."""

    def __init__(self):
        self.name = "Rule-Based"
        self.rules = {sev: [kw.lower() for kw in kws] for sev, kws in KEYWORDS.items()}

    def classify(self, description: str) -> Tuple[str, float, str]:
        text = description.lower()
        scores = {sev: 0.0 for sev in SEVERITIES}

        # Tier 1: structured keyword rules
        for sev, keywords in self.rules.items():
            matches = sum(1 for kw in keywords if kw in text)
            if matches > 0:
                scores[sev] = matches * BASE_WEIGHTS[sev]

        # Check for single clear winner
        max_score = max(scores.values())
        if max_score > 0:
            winners = [s for s, v in scores.items() if v == max_score]
            if len(winners) == 1:
                conf = min(1.0, max_score / 10.0)
                return winners[0], conf, "rule"

        # Tier 2: keyword fallback with length normalization
        kw_scores = {sev: 0.0 for sev in SEVERITIES}
        tokens = _tokenize(text)
        for sev, keywords in self.rules.items():
            for kw in keywords:
                if " " in kw:
                    if kw in text:
                        kw_scores[sev] += BASE_WEIGHTS[sev] + 0.2 * len(kw.split())
                elif kw in tokens:
                    kw_scores[sev] += BASE_WEIGHTS[sev] + 0.2

        # Normalize by sqrt(length)
        norm = math.sqrt(max(1, len(tokens)))
        for sev in kw_scores:
            kw_scores[sev] /= norm

        best_sev = max(kw_scores, key=kw_scores.get)
        best_score = kw_scores[best_sev]

        # Conservative default: High when no evidence
        if best_score == 0:
            return "High", 0.05, "keyword_fallback_no_match"

        conf = min(1.0, best_score / 5.0)
        return best_sev, conf, "keyword"

    def predict(self, description: str) -> str:
        return self.classify(description)[0]


# ═══════════════════════════════════════════════════════════
# Keyword-Only Baseline
# ═══════════════════════════════════════════════════════════
class KeywordClassifier:
    """Keyword-only classifier without structured rule tier."""

    def __init__(self):
        self.name = "Keyword Baseline"
        self.keywords = {sev: [kw.lower() for kw in kws] for sev, kws in KEYWORDS.items()}

    def classify(self, description: str) -> Tuple[str, float, str]:
        text = description.lower()
        tokens = _tokenize(text)
        scores = {sev: 0.0 for sev in SEVERITIES}

        for sev, keywords in self.keywords.items():
            for kw in keywords:
                if " " in kw:
                    if kw in text:
                        scores[sev] += BASE_WEIGHTS[sev] + 0.2 * len(kw.split())
                elif kw in tokens:
                    scores[sev] += BASE_WEIGHTS[sev] + 0.2

        norm = math.sqrt(max(1, len(tokens)))
        for sev in scores:
            scores[sev] /= norm

        best = max(scores, key=scores.get)
        score = scores[best]
        if score == 0:
            return "High", 0.05, "no_match"
        return best, min(1.0, score / 5.0), "keyword"

    def predict(self, description: str) -> str:
        return self.classify(description)[0]


# ═══════════════════════════════════════════════════════════
# FastText-Style N-Gram Baseline
# ═══════════════════════════════════════════════════════════
class FastTextStyleClassifier:
    """Lightweight n-gram pattern matcher (NOT Facebook FastText)."""

    def __init__(self):
        self.name = "FastText-Style"
        self.patterns = NGRAM_PATTERNS
        self.pattern_to_sev = self._assign_patterns()

    def _assign_patterns(self) -> Dict[str, str]:
        mapping = {}
        for pat in self.patterns:
            p = pat.lower()
            best_sev = "High"
            max_score = 0
            for sev, kws in KEYWORDS.items():
                score = sum(1 for kw in kws if p in kw.lower() or kw.lower() in p)
                if score > max_score:
                    max_score = score
                    best_sev = sev
            mapping[p] = best_sev
        return mapping

    def predict(self, description: str) -> str:
        text = description.lower()
        scores = Counter()
        for pat, sev in self.pattern_to_sev.items():
            if pat in text:
                scores[sev] += 1
        if not scores:
            return "High"
        return scores.most_common(1)[0][0]


# ═══════════════════════════════════════════════════════════
# TF-IDF + Logistic Regression
# ═══════════════════════════════════════════════════════════
class TfidfLogisticClassifier:
    """TF-IDF + Logistic Regression as statistical ceiling."""

    def __init__(self, max_features: int = 5000):
        self.name = "TF-IDF + LR"
        self.max_features = max_features
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.weights: Optional[np.ndarray] = None
        self.bias: Optional[np.ndarray] = None

    def _build_vocab(self, texts: List[str]):
        df = Counter()
        for t in texts:
            unique = set(_tokenize(t))
            for w in unique:
                df[w] += 1
        # Select top features by document frequency
        top = df.most_common(self.max_features)
        self.vocab = {w: i for i, (w, _) in enumerate(top)}
        n = len(texts)
        self.idf = {w: math.log((n + 1) / (c + 1)) + 1 for w, c in top}

    def _vectorize(self, text: str) -> np.ndarray:
        vec = np.zeros(len(self.vocab))
        tokens = _tokenize(text)
        tf = Counter(tokens)
        for w, c in tf.items():
            if w in self.vocab:
                vec[self.vocab[w]] = c * self.idf.get(w, 1.0)
        # L2 normalize
        norm = np.linalg.norm(vec)
        if norm > 0:
            vec /= norm
        return vec

    def fit(self, texts: List[str], labels: List[str]):
        self._build_vocab(texts)
        X = np.array([self._vectorize(t) for t in texts])
        y = np.array([SEV_IDX[l] for l in labels])

        # Multiclass one-vs-rest logistic regression
        n_classes = len(SEVERITIES)
        n_features = len(self.vocab)
        self.weights = np.zeros((n_classes, n_features))
        self.bias = np.zeros(n_classes)

        lr = 0.5
        for epoch in range(200):
            logits = X @ self.weights.T + self.bias
            # Softmax
            exp = np.exp(logits - np.max(logits, axis=1, keepdims=True))
            probs = exp / np.sum(exp, axis=1, keepdims=True)

            # Gradient
            y_onehot = np.zeros_like(probs)
            y_onehot[np.arange(len(y)), y] = 1
            grad = (probs - y_onehot).T @ X / len(y)
            grad_b = np.mean(probs - y_onehot, axis=0)

            self.weights -= lr * grad
            self.bias -= lr * grad_b

            if epoch == 50:
                lr = 0.1
            elif epoch == 100:
                lr = 0.05

    def predict(self, text: str) -> str:
        x = self._vectorize(text).reshape(1, -1)
        logits = x @ self.weights.T + self.bias
        return SEVERITIES[np.argmax(logits)]


# ═══════════════════════════════════════════════════════════
# Evaluation utilities
# ═══════════════════════════════════════════════════════════
def evaluate_classifier(clf, descriptions: List[str], labels: List[str],
                        verbose: bool = True) -> Dict:
    """Evaluate a classifier and return comprehensive metrics."""
    start = time.time()
    predictions = [clf.predict(d) for d in descriptions]
    elapsed = time.time() - start

    # Accuracy
    correct = sum(1 for p, t in zip(predictions, labels) if p == t)
    accuracy = correct / len(labels)

    # Per-class metrics
    per_class = {}
    for sev in SEVERITIES:
        tp = sum(1 for p, t in zip(predictions, labels) if p == sev and t == sev)
        fp = sum(1 for p, t in zip(predictions, labels) if p == sev and t != sev)
        fn = sum(1 for p, t in zip(predictions, labels) if p != sev and t == sev)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        per_class[sev] = {"precision": precision, "recall": recall, "f1": f1}

    # Weighted metrics
    class_counts = Counter(labels)
    weights = {s: class_counts[s] / len(labels) for s in SEVERITIES}
    w_precision = sum(per_class[s]["precision"] * weights[s] for s in SEVERITIES)
    w_recall = sum(per_class[s]["recall"] * weights[s] for s in SEVERITIES)
    w_f1 = sum(per_class[s]["f1"] * weights[s] for s in SEVERITIES)

    # Cohen's Kappa
    p_o = accuracy
    p_e = sum(weights[s] * predictions.count(s) / len(predictions) for s in SEVERITIES)
    kappa = (p_o - p_e) / (1 - p_e) if (1 - p_e) > 0 else 0

    # Confusion matrix
    cm = np.zeros((4, 4), dtype=int)
    for p, t in zip(predictions, labels):
        cm[SEV_IDX[t]][SEV_IDX[p]] += 1

    # McNemar helper: disagreements with rule-based
    if hasattr(clf, '_disagreements'):
        disagreements = clf._disagreements
    else:
        disagreements = []

    result = {
        "method": getattr(clf, 'name', clf.__class__.__name__),
        "accuracy": accuracy,
        "precision": w_precision,
        "recall": w_recall,
        "f1": w_f1,
        "kappa": kappa,
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "predictions": predictions,
        "time_seconds": elapsed,
        "records_per_second": len(labels) / elapsed if elapsed > 0 else 0,
    }

    if verbose:
        print(f"\n{'='*50}")
        print(f"  {result['method']}")
        print(f"{'='*50}")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  Precision: {w_precision:.4f}")
        print(f"  Recall:    {w_recall:.4f}")
        print(f"  F1:        {w_f1:.4f}")
        print(f"  Kappa:     {kappa:.4f}")
        print(f"  Time:      {elapsed:.3f}s ({result['records_per_second']:.1f} r/s)")

    return result


def mcnemar_test(pred_a: List[str], pred_b: List[str], labels: List[str],
                 name_a: str = "A", name_b: str = "B") -> Dict:
    """McNemar's paired comparison test."""
    n_01 = sum(1 for a, b, t in zip(pred_a, pred_b, labels)
               if a != t and b == t)
    n_10 = sum(1 for a, b, t in zip(pred_a, pred_b, labels)
               if a == t and b != t)

    if n_01 + n_10 == 0:
        chi2, p_value = 0.0, 1.0
    else:
        chi2 = (abs(n_01 - n_10) - 1) ** 2 / (n_01 + n_10) if (n_01 + n_10) > 1 else 0
        from math import erf, sqrt as msqrt
        p_value = 1 - erf(msqrt(chi2 / 2)) if chi2 > 0 else 1.0

    return {
        "comparison": f"{name_a} vs {name_b}",
        "n_01": n_01, "n_10": n_10,
        "chi2": chi2, "p_value": p_value,
        "significant": p_value < 0.05
    }


if __name__ == "__main__":
    print("CyberOnto Engine loaded. Import classes for use.")
