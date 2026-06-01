#!/usr/bin/env python3
"""
transformer_baseline.py
=======================
DistilBERT-based vulnerability severity classifier.
Provides a modern transformer baseline for comparison.

Usage:
    python transformer_baseline.py --train data/synthetic_1200.json \
                                   --test data/real_cves_500.json \
                                   --output results/transformer_results.json

Requirements:
    pip install transformers torch scikit-learn
"""

import argparse
import json
import time
import warnings
from typing import List, Dict

import numpy as np

warnings.filterwarnings("ignore")

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEV_IDX = {s: i for i, s in enumerate(SEVERITIES)}


def load_data(path: str) -> List[Dict]:
    with open(path) as f:
        return json.load(f)


def encode_labels(labels: List[str]) -> List[int]:
    return [SEV_IDX[l] for l in labels]


class DistilBERTClassifier:
    """
    DistilBERT-based severity classifier.
    Uses Hugging Face transformers with lightweight fine-tuning.
    """

    def __init__(self, model_name: str = "distilbert-base-uncased",
                 max_length: int = 128, epochs: int = 3, batch_size: int = 16):
        self.model_name = model_name
        self.max_length = max_length
        self.epochs = epochs
        self.batch_size = batch_size
        self.name = "DistilBERT"
        self.tokenizer = None
        self.model = None
        self.label_map = SEV_IDX

    def _lazy_init(self):
        """Lazy-load heavy dependencies."""
        if self.tokenizer is None:
            try:
                from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
                import torch
                self.tokenizer = DistilBertTokenizerFast.from_pretrained(self.model_name)
                self.model = DistilBertForSequenceClassification.from_pretrained(
                    self.model_name, num_labels=4, id2label={i: s for i, s in enumerate(SEVERITIES)},
                    label2id=SEV_IDX
                )
                self.torch = torch
                self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                self.model.to(self.device)
            except ImportError:
                raise ImportError("transformers and torch required. Run: pip install transformers torch")

    def fit(self, texts: List[str], labels: List[str]):
        """Fine-tune DistilBERT on vulnerability descriptions."""
        self._lazy_init()
        from torch.utils.data import DataLoader, TensorDataset
        import torch

        y = encode_labels(labels)
        encodings = self.tokenizer(texts, truncation=True, padding=True,
                                   max_length=self.max_length, return_tensors="pt")

        dataset = TensorDataset(
            encodings["input_ids"],
            encodings["attention_mask"],
            torch.tensor(y)
        )
        loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)

        optimizer = torch.optim.AdamW(self.model.parameters(), lr=2e-5)
        self.model.train()

        for epoch in range(self.epochs):
            total_loss = 0
            for batch in loader:
                input_ids, attention_mask, labels_batch = [b.to(self.device) for b in batch]
                optimizer.zero_grad()
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask,
                                     labels=labels_batch)
                loss = outputs.loss
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
            print(f"  Epoch {epoch+1}/{self.epochs}, Loss: {total_loss/len(loader):.4f}")

    def predict(self, texts: List[str]) -> List[str]:
        """Predict severity for a list of descriptions."""
        self._lazy_init()
        self.model.eval()
        from torch.utils.data import DataLoader, TensorDataset
        import torch

        encodings = self.tokenizer(texts, truncation=True, padding=True,
                                   max_length=self.max_length, return_tensors="pt")
        dataset = TensorDataset(encodings["input_ids"], encodings["attention_mask"])
        loader = DataLoader(dataset, batch_size=self.batch_size)

        all_preds = []
        with torch.no_grad():
            for batch in loader:
                input_ids, attention_mask = [b.to(self.device) for b in batch]
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                preds = torch.argmax(outputs.logits, dim=1).cpu().numpy()
                all_preds.extend(preds)

        return [SEVERITIES[p] for p in all_preds]

    def predict_single(self, text: str) -> str:
        return self.predict([text])[0]


def compute_metrics(predictions: List[str], labels: List[str]) -> Dict:
    """Compute evaluation metrics matching cyberonto_engine format."""
    from collections import Counter

    correct = sum(1 for p, t in zip(predictions, labels) if p == t)
    accuracy = correct / len(labels)

    class_counts = Counter(labels)
    weights = {s: class_counts[s] / len(labels) for s in SEVERITIES}

    per_class = {}
    for sev in SEVERITIES:
        tp = sum(1 for p, t in zip(predictions, labels) if p == sev and t == sev)
        fp = sum(1 for p, t in zip(predictions, labels) if p == sev and t != sev)
        fn = sum(1 for p, t in zip(predictions, labels) if p != sev and t == sev)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        per_class[sev] = {"precision": precision, "recall": recall, "f1": f1}

    w_precision = sum(per_class[s]["precision"] * weights[s] for s in SEVERITIES)
    w_recall = sum(per_class[s]["recall"] * weights[s] for s in SEVERITIES)
    w_f1 = sum(per_class[s]["f1"] * weights[s] for s in SEVERITIES)

    p_o = accuracy
    pred_counts = Counter(predictions)
    p_e = sum(weights[s] * pred_counts[s] / len(predictions) for s in SEVERITIES)
    kappa = (p_o - p_e) / (1 - p_e) if (1 - p_e) > 0 else 0

    return {
        "method": "DistilBERT",
        "accuracy": accuracy,
        "precision": w_precision,
        "recall": w_recall,
        "f1": w_f1,
        "kappa": kappa,
        "per_class": per_class,
    }


def main():
    parser = argparse.ArgumentParser(description="DistilBERT baseline for CyberOnto")
    parser.add_argument("--train", required=True, help="Training data JSON")
    parser.add_argument("--test", required=True, help="Test data JSON")
    parser.add_argument("--output", default="../results/transformer_results.json")
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=16)
    args = parser.parse_args()

    print("=" * 60)
    print("  DistilBERT Transformer Baseline")
    print("=" * 60)

    train_data = load_data(args.train)
    test_data = load_data(args.test)

    train_texts = [d["description"] for d in train_data]
    train_labels = [d["severity"] for d in train_data]
    test_texts = [d["description"] for d in test_data]
    test_labels = [d["severity"] for d in test_data]

    print(f"[*] Training: {len(train_texts)} | Test: {len(test_texts)}")

    clf = DistilBERTClassifier(epochs=args.epochs, batch_size=args.batch_size)

    print("[*] Training DistilBERT...")
    t0 = time.time()
    clf.fit(train_texts, train_labels)
    train_time = time.time() - t0

    print(f"[*] Training complete in {train_time:.1f}s")
    print("[*] Predicting on test set...")

    t0 = time.time()
    predictions = clf.predict(test_texts)
    pred_time = time.time() - t0

    metrics = compute_metrics(predictions, test_labels)
    metrics["train_time_seconds"] = train_time
    metrics["prediction_time_seconds"] = pred_time
    metrics["records_per_second"] = len(test_texts) / pred_time

    print(f"\n{'='*50}")
    print(f"  DistilBERT Results")
    print(f"{'='*50}")
    for k in ["accuracy", "precision", "recall", "f1", "kappa"]:
        print(f"  {k.capitalize():12s}: {metrics[k]:.4f}")
    print(f"  Train time : {train_time:.1f}s")
    print(f"  Pred time  : {pred_time:.3f}s ({metrics['records_per_second']:.1f} r/s)")

    with open(args.output, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
