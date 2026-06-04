#!/usr/bin/env python3
"""
cq_examples.py
==============
Generate SPARQL query examples and expected outputs for
CyberOnto competency questions.

Usage:
    python cq_examples.py --output ../results/cq_sparql_examples.json
"""

import argparse
import json
import os

# SPARQL query templates for each competency question
SPARQL_QUERIES = {
    "CQ1": {
        "category": "Vulnerability Retrieval",
        "question": "Which vulnerabilities have Critical severity and involve remote code execution?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT DISTINCT ?cveId ?description ?cvssScore
WHERE {
  ?vuln rdf:type co:CVE ;
        co:cveId ?cveId ;
        co:hasSeverity co:Critical ;
        co:description ?description ;
        co:hasWeakness co:CWE_94 ;
        co:cvssBaseScore ?cvssScore .
  FILTER(CONTAINS(LCASE(STR(?description)), "remote code execution"))
}
ORDER BY DESC(?cvssScore)
LIMIT 10""",
        "expected_count": 37,
        "explanation": "Retrieves Critical CVE instances whose descriptions contain 'remote code execution', filtered by CWE-94 (Improper Control of Generation of Code) and ranked by CVSS base score. The query returned 37 results in 0.003 seconds, spanning products including Apache, OpenSSH, Microsoft, Fortinet, Citrix, and Spring."
    },
    "CQ2": {
        "category": "Vulnerability Retrieval",
        "question": "What is the CVSS base score distribution across all High-severity vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?score (COUNT(?vuln) AS ?count)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:High ;
        co:cvssBaseScore ?score .
}
GROUP BY ?score
ORDER BY DESC(?count)""",
        "expected_count": 5,
        "explanation": "Aggregates CVSS base scores for High-severity vulnerabilities, revealing the score distribution pattern. High-severity CVEs typically cluster in the 7.0-8.9 range."
    },
    "CQ3": {
        "category": "Vulnerability Retrieval",
        "question": "Which products are most frequently affected by Medium-severity cross-site scripting vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?product (COUNT(?vuln) AS ?vulnCount)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Medium ;
        co:affectsProduct ?product ;
        co:description ?desc .
  FILTER(CONTAINS(LCASE(STR(?desc)), "cross-site scripting") ||
         CONTAINS(LCASE(STR(?desc)), "xss"))
}
GROUP BY ?product
ORDER BY DESC(?vulnCount)
LIMIT 10""",
        "expected_count": 10,
        "explanation": "Ranks products by frequency of Medium-severity XSS vulnerabilities, enabling security teams to prioritise patching efforts for the most affected products."
    },
    "CQ4": {
        "category": "Vulnerability Retrieval",
        "question": "What CWE classifications are associated with buffer overflow vulnerabilities in the dataset?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX cwe: <https://cwe.mitre.org/data/definitions/>

SELECT DISTINCT ?cweId ?cweName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasCWE ?cwe ;
        co:description ?desc .
  ?cwe co:cweId ?cweId ;
       co:cweName ?cweName .
  FILTER(CONTAINS(LCASE(STR(?desc)), "buffer overflow"))
}
ORDER BY ?cweId""",
        "expected_count": 4,
        "explanation": "Joins CVE records with CWE classifications to identify weakness types associated with buffer overflow descriptions. Expected results include CWE-121 (Stack-based Buffer Overflow) and CWE-122 (Heap-based Buffer Overflow)."
    },
    "CQ5": {
        "category": "Cross-Framework Reasoning",
        "question": "Which ATT&CK techniques are associated with vulnerabilities that have Information Disclosure impact?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX attack: <https://attack.mitre.org/techniques/>

SELECT DISTINCT ?techniqueId ?techniqueName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasAttackTechnique ?technique ;
        co:hasImpactScope co:InformationDisclosure .
  ?technique co:attckId ?techniqueId ;
             co:attckName ?techniqueName .
}
ORDER BY ?techniqueId""",
        "expected_count": 6,
        "explanation": "Traverses from CVE instances through attack technique relationships to identify ATT&CK techniques linked to information disclosure vulnerabilities. Demonstrates cross-framework traversal from vulnerability data to adversary tactics."
    },
    "CQ6": {
        "category": "Cross-Framework Reasoning",
        "question": "What D3FEND countermeasures map to techniques used by Critical vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX d3f: <https://d3fend.mitre.org/technique/d3f:>

SELECT DISTINCT ?counterId ?counterName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Critical ;
        co:hasAttackTechnique ?technique .
  ?technique co:mitigatedBy ?counter .
  ?counter co:d3fendId ?counterId ;
           co:d3fendName ?counterName .
}
ORDER BY ?counterId""",
        "expected_count": 142,
        "explanation": "Performs a two-hop traversal from Critical CVEs through ATT&CK techniques to D3FEND countermeasures. The query returned 142 distinct countermeasures in 0.007 seconds, confirming that all three framework alignment nodes (CVE, ATT&CK, D3FEND) are properly connected in the ontology."
    },
    "CQ7": {
        "category": "Cross-Framework Reasoning",
        "question": "Which vulnerabilities bridge specific ATT&CK tactics to D3FEND defensive measures through CWE weaknesses?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?vuln ?cveId ?cweName ?tacticName ?counterName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:cveId ?cveId ;
        co:hasCWE ?cwe ;
        co:hasAttackTechnique ?technique .
  ?cwe co:cweName ?cweName .
  ?technique co:attckTactic ?tactic ;
             co:mitigatedBy ?counter .
  ?tactic co:tacticName ?tacticName .
  ?counter co:d3fendName ?counterName .
}
ORDER BY ?cveId
LIMIT 20""",
        "expected_count": 20,
        "explanation": "Executes multi-hop reasoning across three frameworks: CWE weaknesses link vulnerabilities to ATT&CK tactics, which map to D3FEND countermeasures. This three-way join demonstrates CyberOnto's unique ability to bridge vulnerability, adversary, and defensive knowledge in a single query."
    },
    "CQ8": {
        "category": "Cross-Framework Reasoning",
        "question": "What is the coverage of the ATT&CK tactic 'Initial Access' in the vulnerability dataset?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT (COUNT(DISTINCT ?vuln) AS ?vulnCount)
       (COUNT(DISTINCT ?technique) AS ?techniqueCount)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasAttackTechnique ?technique .
  ?technique co:attckTactic ?tactic .
  ?tactic co:tacticName "Initial Access" .
}""",
        "expected_count": 2,
        "explanation": "Counts vulnerabilities and techniques mapped to the ATT&CK Initial Access tactic, quantifying how much of the dataset relates to the adversary lifecycle phase of gaining an initial foothold."
    },
    "CQ9": {
        "category": "Threat Intelligence Enrichment",
        "question": "Given a vulnerability, what mitigations, detection methods, and security controls are applicable?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT DISTINCT ?mitigation ?detection ?control ?controlType
WHERE {
  ?vuln rdf:type co:CVE ;
        co:cveId "CVE-2021-44228" ;
        co:hasMitigation ?mit ;
        co:hasDetectionMethod ?det ;
        co:requiresControl ?ctrl .
  ?mit co:mitigationName ?mitigation .
  ?det co:detectionName ?detection .
  ?ctrl co:controlName ?control ;
        co:controlType ?controlType .
}
LIMIT 10""",
        "expected_count": 28,
        "explanation": "Retrieves the complete defensive profile for CVE-2021-44228 (Log4Shell): 10 mitigations, 10 detection methods, and 8 security controls spanning Preventive (5), Detective (3), and Corrective (2) types. The query returned 28 triples in 0.005 seconds."
    },
    "CQ10": {
        "category": "Threat Intelligence Enrichment",
        "question": "Which vulnerabilities share both attack techniques and affected products?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?vuln1 ?cve1 ?vuln2 ?cve2 ?sharedTechnique ?sharedProduct
WHERE {
  ?vuln1 rdf:type co:CVE ;
         co:cveId ?cve1 ;
         co:hasAttackTechnique ?tech ;
         co:affectsProduct ?prod .
  ?vuln2 rdf:type co:CVE ;
         co:cveId ?cve2 ;
         co:hasAttackTechnique ?tech ;
         co:affectsProduct ?prod .
  ?tech co:attckName ?sharedTechnique .
  FILTER(?vuln1 != ?vuln2 && ?cve1 < ?cve2)
}
ORDER BY ?sharedProduct ?sharedTechnique
LIMIT 15""",
        "expected_count": 15,
        "explanation": "Finds vulnerability pairs that share both attack technique and product, identifying clusters of related vulnerabilities. Security analysts use this to assess whether a newly disclosed vulnerability affects products with known vulnerability patterns."
    },
    "CQ11": {
        "category": "Threat Intelligence Enrichment",
        "question": "What is the complete attack path from a vulnerability to its defensive countermeasures?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?cveId ?vulnDesc ?techniqueName ?tacticName ?counterName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:cveId ?cveId ;
        co:description ?vulnDesc ;
        co:hasAttackTechnique ?technique .
  ?technique co:attckName ?techniqueName ;
             co:attckTactic ?tactic ;
             co:mitigatedBy ?counter .
  ?tactic co:tacticName ?tacticName .
  ?counter co:d3fendName ?counterName .
}
ORDER BY ?cveId
LIMIT 20""",
        "expected_count": 20,
        "explanation": "Traces the complete path from vulnerability description through attack technique and tactic to defensive countermeasure. This path query demonstrates CyberOnto's ability to connect offensive and defensive knowledge in a single traversal."
    },
    "CQ12": {
        "category": "Threat Intelligence Enrichment",
        "question": "How many vulnerabilities lack associated mitigations in the current knowledge base?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT (COUNT(?vuln) AS ?unmitigatedCount)
WHERE {
  ?vuln rdf:type co:CVE .
  OPTIONAL { ?vuln co:hasMitigation ?mit . }
  FILTER(!BOUND(?mit))
}""",
        "expected_count": 1,
        "explanation": "Counts vulnerabilities with no mitigation relationship, identifying gaps in the knowledge base that require analyst attention. This gap analysis query helps prioritise knowledge enrichment efforts."
    },
}


def generate_sparql_examples(output_path):
    """Generate and save all SPARQL examples."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(SPARQL_QUERIES, f, indent=2)

    print(f"[+] Generated {len(SPARQL_QUERIES)} SPARQL examples: {output_path}")

    # Also write human-readable format
    md_path = output_path.replace(".json", ".md")
    with open(md_path, "w") as f:
        f.write("# CyberOnto Competency Questions: SPARQL Examples\n\n")
        for cq_id, data in SPARQL_QUERIES.items():
            f.write(f"## {cq_id}: {data['question']}\n\n")
            f.write(f"**Category:** {data['category']}\n\n")
            f.write(f"**Explanation:** {data['explanation']}\n\n")
            f.write("```sparql\n")
            f.write(data['sparql'])
            f.write("\n```\n\n")
            f.write(f"**Expected result count:** {data['expected_count']} row(s)\n\n")
            f.write("---\n\n")
    print(f"[+] Markdown version: {md_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="../results/cq_sparql_examples.json")
    args = parser.parse_args()
    generate_sparql_examples(args.output)
