# CyberOnto

CyberOnto is an explainable ontology framework for transparent vulnerability triage, combining a fully auditable rule-based classification pipeline with a comprehensive OWL ontology aligned to MITRE ATT&CK, D3FEND, and CWE.

## Overview

The framework provides:

- **Transparent rule-based severity triage** -- every decision is fully inspectable
- **OWL ontology** with 25 classes, 6,079 individuals, and 29,182 triples
- **Cross-framework alignment** with MITRE ATT&CK, D3FEND, and CWE
- **12 competency questions** with SPARQL query examples for validation
- **Benchmark analysis** across synthetic (n=1,200) and held-out (n=500) datasets

## Repository Structure

```
cyberonto/
|-- scripts/              # Python source code
|   |-- run_experiments.py        # Main experimental pipeline
|   |-- cyberonto_engine.py       # Core classification engine
|   |-- build_ontology.py         # OWL ontology constructor
|   |-- fetch_real_cves.py        # CVE dataset fetcher
|   |-- cq_validation.py          # Competency question validator
|   |-- cq_examples.py            # SPARQL query generator
|   |-- transformer_baseline.py   # DistilBERT baseline
|-- data/
|   |-- synthetic_1200.json       # Synthetic dataset (1,200 records)
|   |-- real_cves_500.json        # Held-out CVE dataset (500 records)
|   |-- cve_dataset.json           # Full CVE collection
|-- results/
|   |-- all_results.json          # Complete evaluation results
|   |-- phase6_report.json        # Phase 6 summary report
|   |-- cyberonto_stats.json      # Ontology construction statistics
|   |-- cq_sparql_examples.json   # CQ SPARQL query collection
|   |-- cq_sparql_examples.md     # CQ SPARQL query documentation
|-- figures/               # Generated visualisations
|   |-- fig1_classification_comparison.png
|   |-- fig2_confusion_matrices.png
|   |-- fig3_kappa.png
|   |-- fig4_mcnemar.png
|   |-- fig5_perclass_f1.png
|   |-- fig6_real_vs_synthetic.png
|   |-- fig7_dashboard.png
|   |-- fig8_ontology.png
|-- CyberOnto.tex         # LaTeX source
|-- cyberonto.bib         # Bibliography
```

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Install Dependencies

```bash
pip install scikit-learn pandas numpy matplotlib seaborn owlready2
```

### Run the Complete Pipeline

```bash
cd scripts
python run_experiments.py --run-all
```

This executes all 7 phases: dataset preparation, ontology building, synthetic evaluation, held-out evaluation, statistical testing, report generation, and figure creation.

### Run Individual Phases

```bash
python run_experiments.py --phases 1    # Dataset preparation only
python run_experiments.py --phases 2    # Ontology building only
python run_experiments.py --phases 3    # Synthetic evaluation only
python run_experiments.py --phases 4    # Held-out evaluation only
python run_experiments.py --phases 5    # Statistical tests only
python run_experiments.py --phases 6    # Report generation only
python run_experiments.py --phases 7    # Figure generation only
```

## Experimental Results

### Phase 1: Datasets

| Dataset | Records | Critical | High | Medium | Low |
|---------|---------|----------|------|--------|-----|
| Synthetic | 1,200 | 144 | 336 | 456 | 264 |
| Held-out | 500 | 60 | 140 | 190 | 110 |

The synthetic dataset uses template-generated descriptions with distinctive vocabulary per severity class. The held-out set combines 100 authentic NVD records with 400 independently generated realistic templates.

### Phase 2: Ontology

| Metric | Count |
|--------|-------|
| Classes | 25 |
| Object Properties | 13 |
| Datatype Properties | 13 |
| Individuals | 6,079 |
| Triples | 29,182 |
| Competency Questions Passed | 12/12 |

All 12 competency questions execute successfully:

| CQ | Category | Question | Status |
|----|----------|----------|--------|
| CQ1 | Vulnerability Retrieval | Critical RCE vulnerabilities | PASS (135 results) |
| CQ2 | Vulnerability Retrieval | CVSS score distribution | PASS |
| CQ3 | Vulnerability Retrieval | XSS product ranking | PASS (26 results) |
| CQ4 | Vulnerability Retrieval | CWE classification | PASS |
| CQ5 | Cross-Framework Reasoning | ATT&CK technique mapping | PASS (100% coverage) |
| CQ6 | Cross-Framework Reasoning | D3FEND countermeasure mapping | PASS (2400 results) |
| CQ7 | Cross-Framework Reasoning | Multi-hop reasoning | PASS (1200 results) |
| CQ8 | Cross-Framework Reasoning | Initial Access coverage | PASS |
| CQ9 | Threat Intelligence | Complete defensive profile | PASS (1200 results) |
| CQ10 | Threat Intelligence | Similar vulnerability pairs | PASS |
| CQ11 | Threat Intelligence | Attack path tracing | PASS (3 results) |
| CQ12 | Threat Intelligence | Mitigation gap analysis | PASS (100% coverage) |

### Phase 3: Synthetic Data Evaluation (n=1,200)

| Method | Accuracy | Precision | Recall | F1 | Kappa | Time (s) |
|--------|----------|-----------|--------|-----|-------|----------|
| Rule-Based | 0.7342 | 0.7868 | 0.7342 | 0.7213 | 0.6338 | 0.043 |
| Keyword Baseline | 0.7892 | 0.8267 | 0.7892 | 0.7753 | 0.7021 | 0.072 |
| TF-IDF + LR | 0.8817 | 0.9000 | 0.8817 | 0.8303 | 0.8279 | 0.078 |
| FastText-Style | 0.3233 | 0.1586 | 0.3233 | 0.1983 | 0.0846 | 0.011 |
| Majority Baseline | 0.3800 | 0.1444 | 0.3800 | 0.2093 | 0.0000 | <0.001 |
| Random Baseline | 0.2600 | 0.2997 | 0.2600 | 0.2705 | 0.0144 | <0.001 |

### Phase 4: Held-Out Evaluation (n=500)

| Method | Accuracy | Precision | Recall | F1 | Kappa | Time (s) |
|--------|----------|-----------|--------|-----|-------|----------|
| Rule-Based | 0.3300 | 0.2488 | 0.3300 | 0.2279 | 0.1053 | 0.025 |
| Keyword Baseline | 0.3780 | 0.3002 | 0.3780 | 0.2694 | 0.1484 | 0.031 |
| TF-IDF + LR | 0.4240 | 0.5499 | 0.4240 | 0.3863 | 0.1721 | 0.039 |
| FastText-Style | 0.3440 | 0.1765 | 0.3440 | 0.2138 | 0.1102 | 0.005 |
| Majority Baseline | 0.3800 | 0.1444 | 0.3800 | 0.2093 | 0.0000 | <0.001 |
| Random Baseline | 0.2440 | 0.2884 | 0.2440 | 0.2561 | -0.0046 | <0.001 |

### Phase 5: McNemar's Statistical Significance Tests

| Comparison | Chi-Squared | p-Value | Significant |
|------------|-------------|---------|-------------|
| Rule-Based vs Keyword | 55.59 | <0.0001 | Yes |
| Rule-Based vs TF-IDF | 67.19 | <0.0001 | Yes |
| Rule-Based vs FastText | 491.00 | <0.0001 | Yes |
| Rule-Based vs Majority | 250.73 | <0.0001 | Yes |
| Rule-Based vs Random | 438.94 | <0.0001 | Yes |
| Keyword vs FastText | 491.00 | <0.0001 | Yes |

### Key Findings

1. **Synthetic performance**: The Rule-Based engine achieves 73.42% accuracy with substantial agreement (kappa = 0.634). The TF-IDF ceiling at 88.17% quantifies the maximum statistical signal in synthetic data.

2. **Cross-domain generalisation gap**: All methods experience substantial declines on held-out descriptions. The Rule-Based engine drops 40.42 percentage points (73.42% to 33.00%). The TF-IDF baseline drops 45.77 percentage points (88.17% to 42.40%).

3. **Processing speed**: The FastText-Style Baseline processes 105,179 records/second. The Rule-Based engine processes 28,233 records/second. All keyword methods complete 1,200-record batches in under 100 milliseconds.

4. **Ontology validation**: All 12 competency questions pass, confirming cross-framework reasoning and threat intelligence enrichment capabilities.

## Individual Scripts

### Core Engine

```bash
python cyberonto_engine.py
```

Runs the standalone rule-based triage engine with sample vulnerability descriptions.

### Ontology Builder

```bash
python build_ontology.py
```

Constructs the full OWL ontology with MITRE ATT&CK, D3FEND, and CWE alignments. Outputs `cyberonto.owl`.

### CVE Fetcher

```bash
python fetch_real_cves.py
```

Fetches authentic CVE records from the NVD API and generates realistic template-based descriptions.

### Competency Question Validator

```bash
python cq_validation.py
```

Executes all 12 SPARQL competency questions against the constructed ontology and reports pass/fail status.

### SPARQL Examples

```bash
python cq_examples.py
```

Generates documented SPARQL query examples for all 12 competency questions.

### Transformer Baseline

```bash
python transformer_baseline.py
```

Runs the DistilBERT baseline comparison (optional, requires `transformers` library).

## Data Files

### `data/synthetic_1200.json`

1,200 synthetic vulnerability records with severity labels. Distribution: 144 Critical, 336 High, 456 Medium, 264 Low.

### `data/real_cves_500.json`

500 held-out vulnerability descriptions: 100 authentic NVD records + 400 realistic templates. Distribution: 60 Critical, 140 High, 190 Medium, 110 Low.

### `results/all_results.json`

Complete evaluation results including per-class metrics, confusion matrices, timing data, and McNemar's test statistics.

### `results/phase6_report.json`

Structured summary report with best method identification and ontology validation status.

## Figures

Eight visualisations are generated in the `figures/` directory:

1. **fig1** -- Classification comparison (6 methods, synthetic data)
2. **fig2** -- Confusion matrices (all methods)
3. **fig3** -- Cohen's kappa with Landis & Koch zones
4. **fig4** -- McNemar's test significance heatmap
5. **fig5** -- Per-class F1 scores
6. **fig6** -- Synthetic vs held-out accuracy comparison
7. **fig7** -- Four-panel comprehensive dashboard
8. **fig8** -- Ontology structure diagram

## Citation

```bibtex
@article{cyberonto2026,
  title={CyberOnto: An Explainable Ontology Framework for Transparent Vulnerability Triage with Cross-Domain Benchmark Analysis},
  journal={Applied Ontology},
  year={2026},
  note={Under review}
}
```

## License

This project is released as open-source software to support reproducibility and community extension. All experimental scripts, datasets, and ontology files are included in this repository.
