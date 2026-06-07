# CyberOnto: Explainable Ontology Framework for Vulnerability Triage

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Transparent, rule-based vulnerability severity triage with OWL ontology integration aligned to MITRE ATT&CK, D3FEND, and CWE.**

---

## Overview

CyberOnto is a research framework that combines:
- **Explainable rule-based triage engine** with full auditability
- **OWL ontology** (25 classes, 26 properties, ~6,079 individuals, ~29,182 triples)
- **Cross-framework reasoning** via SPARQL queries across ATT&CK, D3FEND, and CWE
- **Benchmark analysis** exposing the generalisation gap between synthetic and real CVE data

**Key Design Principle**: Interpretability over accuracy. The system provides auditable severity assessments that analysts can verify, override, or refine — not opaque predictions.

---

## Repository Structure

```
CyberOnto/
├── scripts/
│   ├── build_ontology.py          # OWL ontology construction
│   ├── cq_examples.py              # SPARQL competency question execution
│   ├── cq_validation.py            # CQ validation against live ontology
│   ├── cyberonto_engine.py         # Classification engines (Rule-Based, TF-IDF, etc.)
│   ├── fetch_real_cves.py         # NVD API fetch (with fallback generation)
│   ├── run_experiments.py         # Complete experimental pipeline (Phases 1-7)
│   └── transformer_baseline.py   # DistilBERT baseline (optional)
├── data/                           # Generated datasets and ontology
│   ├── synthetic_1200.json
│   ├── real_cves_500.json
│   ├── cyberonto.owl
│   ├── cyberonto_stats.json
│   └── cyberonto_cq_validation.json
├── results/                        # Experimental results
│   ├── all_results.json
│   ├── phase6_report.json
│   └── cq_sparql_examples.json
└── figures/                        # Generated visualisations
    ├── fig1_classification_comparison.png
    ├── fig2_confusion_matrices.png
    ├── fig3_kappa.png
    ├── fig4_mcnemar.png
    ├── fig5_perclass_f1.png
    ├── fig6_real_vs_synthetic.png
    ├── fig7_dashboard.png
    └── fig8_ontology.png
```

---

## Installation

```bash
# Clone repository
git clone https://github.com/slimnithbt135/CyberOnto.git
cd CyberOnto

# Install dependencies
pip install owlready2 rdflib numpy matplotlib

# Optional: for transformer baseline
pip install transformers torch scikit-learn
```

---

## Quick Start

### 1. Run Complete Pipeline

```bash
cd scripts
python run_experiments.py --run-all
```

This executes all 7 phases:
1. **Dataset generation** (synthetic n=1,200 + real CVE n=500)
2. **Ontology building** with CQ validation
3. **Synthetic data classification** evaluation
4. **Real CVE cross-domain** evaluation
5. **McNemar's statistical** significance tests
6. **Report generation**
7. **Figure generation**

### 2. Run SPARQL Competency Questions

```bash
python cq_examples.py --output ../results/cq_sparql_examples.json
```

Executes 12 SPARQL queries against the live ontology and saves actual results with timing measurements.

### 3. Run Ontology Validation Only

```bash
python build_ontology.py --output ../data/cyberonto.owl --validate
```

---

## Actual Experimental Results

### Ontology Construction

| Metric | Count |
|--------|-------|
| Classes | 25 |
| Object Properties | 13 |
| Datatype Properties | 13 |
| Individuals | 6,079 |
| Triples | 29,182 |
| Competency Questions Passed | 12/12 |

### Classification Performance (Synthetic Data, n=1,200)

| Method | Accuracy | Precision | Recall | F1 | Kappa | Time (s) |
|--------|----------|-----------|--------|-----|-------|----------|
| Rule-Based | 0.7342 | 0.7868 | 0.7342 | 0.7213 | 0.6338 | 0.040 |
| Keyword Baseline | 0.7892 | 0.8267 | 0.7892 | 0.7753 | 0.7021 | 0.047 |
| TF-IDF + LR (in-sample) | 0.8817 | 0.9000 | 0.8817 | 0.8303 | 0.8279 | 0.065 |
| FastText-Style | 0.3233 | 0.1586 | 0.3233 | 0.1983 | 0.0846 | 0.012 |
| Majority Baseline | 0.3800 | 0.1444 | 0.3800 | 0.2093 | 0.0000 | <0.001 |
| Random Baseline | 0.2600 | 0.2997 | 0.2600 | 0.2705 | 0.0144 | <0.001 |

### Classification Performance (Held-Out Real CVEs, n=500)

| Method | Accuracy | Precision | Recall | F1 | Kappa | Time (s) |
|--------|----------|-----------|--------|-----|-------|----------|
| Rule-Based | 0.3300 | 0.2488 | 0.3300 | 0.2279 | 0.1053 | 0.021 |
| Keyword Baseline | 0.3780 | 0.3002 | 0.3780 | 0.2694 | 0.1484 | 0.027 |
| TF-IDF + LR (cross-domain) | 0.4240 | 0.5499 | 0.4240 | 0.3863 | 0.1721 | 0.038 |
| FastText-Style | 0.3440 | 0.1765 | 0.3440 | 0.2138 | 0.1102 | 0.005 |
| Majority Baseline | 0.3800 | 0.1444 | 0.3800 | 0.2093 | 0.0000 | <0.001 |
| Random Baseline | 0.2440 | 0.2884 | 0.2440 | 0.2561 | -0.0046 | <0.001 |

### McNemar's Test (Synthetic Data)

| Comparison | χ² | p-Value | Significant |
|------------|-----|---------|-------------|
| Rule-Based vs Keyword Baseline | 55.59 | <0.0001 | *** |
| Rule-Based vs TF-IDF + LR | 67.19 | <0.0001 | *** |
| Rule-Based vs FastText-Style | 491.00 | <0.0001 | *** |
| Rule-Based vs Majority Baseline | 250.73 | <0.0001 | *** |
| Rule-Based vs Random Baseline | 438.94 | <0.0001 | *** |
| Keyword Baseline vs FastText-Style | 491.00 | <0.0001 | *** |

### Competency Question Validation Results (Python Object Traversal)

| CQ | Category | Status | Results | Time (s) |
|----|----------|--------|---------|----------|
| CQ1 | Vulnerability Retrieval | PASS | 135 Critical RCE CVEs | 0.228 |
| CQ2 | Vulnerability Retrieval | PASS | CVSS distribution shown | 0.006 |
| CQ3 | Vulnerability Retrieval | PASS | 26 XSS products | 0.007 |
| CQ4 | Vulnerability Retrieval | PASS | CWE groups exist | 0.009 |
| CQ5 | Cross-Framework Reasoning | PASS | 100% technique coverage | 0.006 |
| CQ6 | Cross-Framework Reasoning | PASS | 8 distinct countermeasures | 0.004 |
| CQ7 | Cross-Framework Reasoning | PASS | 1,200 multi-hop paths | 1.990 |
| CQ8 | Cross-Framework Reasoning | PASS | 10.0% Initial Access | 0.001 |
| CQ9 | Threat Intelligence | PASS | 1,200 defensive profiles | 0.012 |
| CQ10 | Threat Intelligence | PASS | Similarity groups exist | 0.016 |
| CQ11 | Threat Intelligence | PASS | 3 campaign paths | 0.000 |
| CQ12 | Threat Intelligence | PASS | 100% mitigation coverage | 0.006 |
| **Total** | | **12/12 PASS** | | **2.283** |

### Competency Question SPARQL Results (RDF Graph Pattern Matching)

| CQ | Category | Results | Execution Time |
|----|----------|---------|----------------|
| CQ1 | Vulnerability Retrieval | 23 rows | 0.443s |
| CQ2 | Vulnerability Retrieval | 1 row | 0.108s |
| CQ3 | Vulnerability Retrieval | 21 rows | 0.402s |
| CQ4 | Vulnerability Retrieval | 1 row | 0.559s |
| CQ5 | Cross-Framework Reasoning | 4 rows | 0.899s |
| CQ6 | Cross-Framework Reasoning | 4 rows | 0.123s |
| CQ7 | Cross-Framework Reasoning | 2,400 rows | 1.715s |
| CQ8 | Cross-Framework Reasoning | 1 row | 0.027s |
| CQ9 | Threat Intelligence | 1,200 rows | 1.024s |
| CQ10 | Threat Intelligence | 20,126 rows | 238.364s |
| CQ11 | Threat Intelligence | 2,400 rows | 1.709s |
| CQ12 | Threat Intelligence | 1 row | 0.427s |
| **Total** | | | **245.799s** |

**Note on Validation vs SPARQL Differences**: The validation module (Python object traversal) and SPARQL queries (RDF graph pattern matching) measure different aspects of the ontology. Validation checks structural integrity and property coverage, while SPARQL returns specific matching triple patterns. Both are valid but produce different counts. For example:
- CQ1 validation counts all Critical CVEs with RCE-related techniques (135), while SPARQL further filters for CWE-94 and "remote code execution" in the description (23).
- CQ11 validation counts campaign-to-actor paths (3 campaigns), while SPARQL counts CVE-to-technique-to-tactic-to-countermeasure paths (2,400 combinatorial).

**Environment**: Windows 10, Python 3.11, Intel i7, 16GB RAM, SSD.

---

## Important Notes on Reproducibility

### What the Numbers Mean

1. **Synthetic vs Real CVE Gap**: All methods decline substantially from synthetic to real data (33-45 percentage points). This is a **feature, not a bug** — it demonstrates the challenge of domain transfer in vulnerability analysis.

2. **TF-IDF "88.17%" is an in-sample ceiling**: Trained and tested on the same synthetic data. It quantifies the statistical signal ceiling, not real-world capability.

3. **CQ Result Variability**: SPARQL result counts depend on the specific synthetic data generated. Your counts may differ slightly due to random seed variation in description generation.

4. **Timing Measurements**: All execution times are measured with Python's `time.time()` on the host machine. Times will vary based on hardware (CPU, RAM, disk speed). CQ10 (self-join similarity) is slow due to combinatorial explosion.

5. **NVD API Fetch**: The `fetch_real_cves.py` script attempts to fetch from the NVD API but may fall back to template-generated descriptions due to rate limiting or API unavailability. The held-out set contains ~20% authentic NVD records when API fetch succeeds.

---

## Paper Citation

If you use this framework in your research, please cite:

```bibtex
@article{cyberonto2026,
  title={CyberOnto: An Explainable Ontology Framework for Transparent Vulnerability Triage with Cross-Domain Benchmark Analysis},
  author={[Anonymous]},
  journal={[Journal Title]},
  year={2026},
  volume={XX},
  number={X},
  pages={1--13}
}
```

---

## License

MIT License — see LICENSE file for details.

---

## Acknowledgements

Deanship of Graduate Studies and Scientific Research, Taif University.

---

## Contact

For questions or issues, please open a GitHub issue or contact the corresponding author.

**Repository**: https://github.com/slimnithbt135/CyberOnto
