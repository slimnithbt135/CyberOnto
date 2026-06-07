# CyberOnto Repository Changes Log

## Version 1.1 — June 2026

### Purpose
This document records all corrections made to the CyberOnto repository to ensure full transparency and reproducibility. These changes were made after the initial paper submission to align the code with the actual ontology schema and to replace placeholder values with measured values.

---

## Changes Made

### 1. SPARQL Query Corrections (`cq_examples.py`)

**Problem**: The original SPARQL queries used property names from an early ontology draft that did not match the final ontology schema built by `build_ontology.py`. This caused queries to return 0 rows or incorrect results when executed against the live ontology.

**Fixes Applied**:
- `co:hasWeakness` → `co:hasCWE` (actual property name in final ontology)
- `co:Critical` → `co:Severity_Critical` (actual severity individual name)
- `co:cvssBaseScore` (direct on CVE) → `co:hasCVSS ?cvss . ?cvss co:cvssBaseScore` (traversing via CVSS instance)
- `co:requiresControl` → `co:hasSecurityControl` (actual property name)
- Added `FILTER(STR(?var) = "value")` pattern to handle `xsd:string` vs plain literal mismatches from owlready2
- Removed hardcoded `CVE-2021-44228` reference in CQ9 (this CVE does not exist in synthetic data)

**Impact**: All 12 CQs now execute correctly and return meaningful results from the synthetic dataset.

---

### 2. Honest Timing Measurements (`cq_examples.py`, `cq_validation.py`)

**Problem**: The original code and paper reported timing estimates (e.g., "0.003s", "0.007s") that were not measured by any code. These were placeholder values from preliminary testing.

**Fixes Applied**:
- Added `time.time()` calls around all SPARQL query executions
- Added `time.time()` calls around all validation function executions
- Reported total execution time and per-query average
- Documented execution environment (Windows 10, Python 3.11, Intel i7, 16GB RAM)

**Actual Measured Times** (from execution on 2026-06-07):

**SPARQL Execution:**

| CQ | Results | Time (s) |
|----|---------|----------|
| CQ1 | 23 rows | 0.443 |
| CQ2 | 1 row | 0.108 |
| CQ3 | 21 rows | 0.402 |
| CQ4 | 1 row | 0.559 |
| CQ5 | 4 rows | 0.899 |
| CQ6 | 4 rows | 0.123 |
| CQ7 | 2,400 rows | 1.715 |
| CQ8 | 1 row | 0.027 |
| CQ9 | 1,200 rows | 1.024 |
| CQ10 | 20,126 rows | 238.364 |
| CQ11 | 2,400 rows | 1.709 |
| CQ12 | 1 row | 0.427 |
| **Total** | | **245.799** |

**Validation Execution:**

| CQ | Results | Time (s) |
|----|---------|----------|
| CQ1 | 135 Critical RCE | 0.228 |
| CQ2 | Distribution shown | 0.006 |
| CQ3 | 26 XSS products | 0.007 |
| CQ4 | CWE groups | 0.009 |
| CQ5 | 100% coverage | 0.006 |
| CQ6 | 8 countermeasures | 0.004 |
| CQ7 | 1,200 paths | 1.990 |
| CQ8 | 10.0% coverage | 0.001 |
| CQ9 | 1,200 profiles | 0.012 |
| CQ10 | Similarity groups | 0.016 |
| CQ11 | 3 campaign paths | 0.000 |
| CQ12 | 100% coverage | 0.006 |
| **Total** | | **2.283** |

**Note**: CQ10 is slow (238s) in SPARQL due to the self-join combinatorial explosion on 1,200 records. This is expected behavior for similarity queries. Validation is faster (0.016s) because it uses Python object traversal rather than RDF graph pattern matching.

---

### 3. Validation Code Fixes (`cq_validation.py`)

**Problem**: The original validation code used property names from an early ontology draft (`hasWeakness`, `requiresControl`) that do not exist in the final ontology. This caused validation to check non-existent properties.

**Fixes Applied**:
- `hasWeakness` → `hasCWE` (all 5 occurrences)
- `requiresControl` → `hasSecurityControl` (1 occurrence)
- Added honest timing to all validation functions
- Fixed CQ8 percentage calculation bug (was showing 10300% due to integer division error)
- Fixed CQ6 to report DISTINCT countermeasures (was reporting total pairs, not unique ones)
- Fixed CQ11 to report actual path count (was hardcoded to 3)

**Impact**: Validation now correctly reflects the final ontology structure and produces accurate counts.

---

### 4. Fix Results (`cq_examples.py`)

**Problem**: correct the values did not match the actual results from the final ontology and synthetic dataset.

**Fixes Applied**:
- Results now show only actual counts from executing against the live ontology
- Added explanatory notes for data-dependent results (e.g., CQ4 returns 0-1 rows depending on whether "buffer overflow" appears in descriptions)

**Impact**: The JSON and Markdown outputs now contain only reproducible results from the actual ontology.

---

### 5. README.md Honest Rewrite

**Problem**: The original README contained placeholder result counts that did not match actual execution.

**Fixes Applied**:
- Replaced all result counts with actual measured values from both validation and SPARQL
- Added "Important Notes on Reproducibility" section explaining data variability
- Added environment specification for timing context
- Clarified that CQ10 slowness is expected due to combinatorial self-join
- Added explanation of validation vs SPARQL differences

---

## What Was NOT Changed

The following remain unchanged and are fully reproducible:

- **Classification accuracy**: 73.42% (synthetic), 33.00% (real) — from actual code
- **Kappa values**: 0.634 (synthetic), 0.105 (real) — from actual code
- **McNemar tests**: All p < 0.0001 — from actual code
- **Ontology stats**: 25 classes, 26 properties, 6,079 individuals, 29,182 triples — from actual code
- **Dataset distributions**: 12% Critical, 28% High, 38% Medium, 22% Low — from actual code

---

## How to Verify These Changes

1. Run the corrected scripts:
   ```bash
   cd scripts
   python cq_examples.py --output ../results/cq_sparql_examples.json
   python run_experiments.py --run-all
   ```

2. Compare your output with the values in this README.

3. Check that all SPARQL queries execute without errors and return non-zero results (except CQ4 which is data-dependent).

---

## Future Work

- Add "buffer overflow" descriptions to synthetic dataset to make CQ4 consistently return non-zero results
- Optimize CQ10 self-join query to reduce execution time
- Add `EXPLAIN` output for SPARQL queries to document query plans
- Include transformer baseline (DistilBERT) in main pipeline
- Expand held-out dataset to >1,000 directly sourced NVD records

---

## Contact

For questions about these changes, please open a GitHub issue.

**Date**: 2026-06-07
**Changed by**: Repository maintainer
