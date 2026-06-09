#!/usr/bin/env python3
"""
cq_examples.py
==============
Generate SPARQL query examples for CyberOnto competency questions,
BUILD the ontology, EXECUTE queries against a live RDF graph,
and return ACTUAL results with HONEST timing measurements.

Usage:
    python cq_examples.py --output ../results/cq_sparql_examples.json
"""

import argparse
import json
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

# ═══════════════════════════════════════════════════════════
# 12 SPARQL Competency Questions (aligned to ACTUAL ontology schema)
# NOTE: All literal comparisons use FILTER(STR(?var) = "value")
#       to avoid xsd:string vs plain literal mismatches from owlready2.
# ═══════════════════════════════════════════════════════════

SPARQL_QUERIES = {
    "CQ1": {
        "category": "Vulnerability Retrieval",
        "question": "Which vulnerabilities in the dataset have Critical severity and involve remote code execution?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT DISTINCT ?cveId ?description ?cvssScore
WHERE {
  ?vuln rdf:type co:CVE ;
        co:cveId ?cveId ;
        co:hasSeverity co:Severity_Critical ;
        co:description ?description ;
        co:hasCWE ?cwe ;
        co:hasCVSS ?cvss .
  ?cwe co:cweId ?cweIdVal .
  ?cvss co:cvssBaseScore ?cvssScore .
  FILTER(STR(?cweIdVal) = "CWE-94")
  FILTER(CONTAINS(LCASE(STR(?description)), "remote code execution"))
}
ORDER BY DESC(?cvssScore)
LIMIT 10""",
        "explanation": "Retrieves Critical CVEs with CWE-94 weakness containing 'remote code execution'. Uses FILTER(STR()) for safe literal matching."
    },
    "CQ2": {
        "category": "Vulnerability Retrieval",
        "question": "What is the CVSS base score distribution across all High-severity vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT ?score (COUNT(?vuln) AS ?count)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Severity_High ;
        co:hasCVSS ?cvss .
  ?cvss co:cvssBaseScore ?score .
}
GROUP BY ?score
ORDER BY DESC(?count)""",
        "explanation": "Aggregates CVSS base scores via hasCVSS -> CVSS for High-severity vulnerabilities."
    },
    "CQ3": {
        "category": "Vulnerability Retrieval",
        "question": "Which products are most frequently affected by Medium-severity cross-site scripting vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT ?product (COUNT(?vuln) AS ?vulnCount)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Severity_Medium ;
        co:affectsProduct ?product ;
        co:description ?desc .
  FILTER(CONTAINS(LCASE(STR(?desc)), "cross-site scripting") ||
         CONTAINS(LCASE(STR(?desc)), "xss"))
}
GROUP BY ?product
ORDER BY DESC(?vulnCount)
LIMIT 10""",
        "explanation": "Ranks products by Medium-severity XSS vulnerability frequency."
    },
    "CQ4": {
        "category": "Vulnerability Retrieval",
        "question": "What CWE classifications are associated with buffer overflow vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT DISTINCT ?cweId ?cweName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasCWE ?cwe ;
        co:description ?desc .
  ?cwe co:cweId ?cweIdVal ;
       co:cweName ?cweName .
  FILTER(CONTAINS(LCASE(STR(?desc)), "buffer overflow"))
}
ORDER BY ?cweIdVal""",
        "explanation": "Joins CVE records with CWE classifications via hasCWE for buffer overflow descriptions."
    },
    "CQ5": {
        "category": "Cross-Framework Reasoning",
        "question": "Which ATT&CK techniques are associated with vulnerabilities that have Information Disclosure impact?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT DISTINCT ?techniqueId ?techniqueName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasCWE ?cwe ;
        co:hasAttackTechnique ?technique .
  ?cwe co:cweName ?cweName .
  ?technique co:attckId ?techniqueId ;
             co:attckName ?techniqueName .
  FILTER(CONTAINS(LCASE(STR(?cweName)), "information disclosure") ||
         CONTAINS(LCASE(STR(?cweName)), "exposure"))
}
ORDER BY ?techniqueId""",
        "explanation": "Traverses CVEs through hasCWE -> CWE to ATT&CK techniques for Information Disclosure."
    },
    "CQ6": {
        "category": "Cross-Framework Reasoning",
        "question": "What D3FEND countermeasures map to the attack techniques used by Critical-severity vulnerabilities?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT DISTINCT ?counterId ?counterName
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Severity_Critical ;
        co:hasAttackTechnique ?technique .
  ?technique co:mitigatedBy ?counter .
  ?counter co:d3fendId ?counterId ;
           co:d3fendName ?counterName .
}
ORDER BY ?counterId""",
        "explanation": "Two-hop traversal: Critical CVEs -> ATT&CK techniques -> D3FEND countermeasures via mitigatedBy."
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
        "explanation": "Multi-hop reasoning across three frameworks: hasCWE -> ATT&CK tactics -> D3FEND."
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
        "explanation": "Counts vulnerabilities and techniques mapped to Initial Access tactic."
    },
    "CQ9": {
        "category": "Threat Intelligence Enrichment",
        "question": "Given a vulnerability, what mitigations, detection methods, and security controls are applicable?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT DISTINCT ?cveId ?mitigation ?detection ?control
WHERE {
  ?vuln rdf:type co:CVE ;
        co:cveId ?cveId ;
        co:hasMitigation ?mit ;
        co:hasDetectionMethod ?det ;
        co:hasSecurityControl ?ctrl .
  ?mit co:mitigationName ?mitigation .
  ?det co:detectionName ?detection .
  ?ctrl co:controlName ?control .
}
ORDER BY ?cveId
LIMIT 10""",
        "explanation": "Retrieves defensive profile for vulnerabilities using hasMitigation, hasDetectionMethod, and hasSecurityControl."
    },
    "CQ10": {
        "category": "Threat Intelligence Enrichment",
        "question": "Which vulnerabilities share both attack techniques and affected products?",
        "sparql": """PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT ?cve1 ?cve2 ?sharedTechnique ?prod
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
ORDER BY ?prod ?sharedTechnique
LIMIT 15""",
        "explanation": "Finds vulnerability pairs sharing both attack technique and product (self-join)."
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
        "explanation": "Traces complete path: vulnerability -> technique -> tactic -> D3FEND countermeasure."
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
        "explanation": "Counts vulnerabilities with no mitigation relationship (gap analysis)."
    },
}


def exec_query(graph, query, max_results=20):
    """Execute SPARQL and return (count, formatted_results)."""
    results = list(graph.query(query))
    formatted = []
    for row in results[:max_results]:
        d = {}
        for var_name, value in row.asdict().items():
            s = str(value.toPython()) if hasattr(value, "toPython") else str(value)
            d[var_name] = s
        formatted.append(d)
    return len(results), formatted


def build_and_execute(output_path, data_dir=None):
    """Build ontology, execute all 12 SPARQL CQs, save results with HONEST timing."""
    try:
        import rdflib
        from rdflib import Graph, Namespace, Literal, RDF, RDFS, OWL, XSD
    except ImportError:
        print("[!] Install rdflib: pip install rdflib")
        sys.exit(1)

    if data_dir is None:
        data_dir = os.path.join(os.path.dirname(output_path), "..", "data")
    data_dir = os.path.abspath(data_dir)
    os.makedirs(data_dir, exist_ok=True)

    # ─── Generate synthetic data if needed ───
    synth_path = os.path.join(data_dir, "synthetic_1200.json")
    if not os.path.exists(synth_path):
        print("[*] Generating synthetic dataset...")
        import random
        random.seed(42)
        SEVERITIES = ["Critical", "High", "Medium", "Low"]
        products = ["Apache HTTP Server", "nginx", "OpenSSL", "OpenSSH", "PostgreSQL",
                    "MySQL", "Microsoft Exchange", "Windows Server", "Linux Kernel",
                    "Docker", "Kubernetes", "Jenkins", "GitLab", "WordPress", "Drupal",
                    "Spring Framework", "Django", "Node.js", "Tomcat", "Elasticsearch",
                    "MongoDB", "Redis", "Kafka", "Grafana", "Cisco IOS", "Fortinet FortiOS",
                    "VMware vSphere", "F5 BIG-IP", "AWS EC2", "Azure AD"]
        descs = {
            "Critical": ["{} contains a remote code execution vulnerability enabling complete system compromise",
                         "{} has a critical SQL injection vulnerability allowing unauthorized data extraction"],
            "High": ["{} has a cross-site scripting vulnerability allowing injection of malicious scripts",
                     "{} has an information disclosure flaw exposing sensitive data"],
            "Medium": ["{} has a reflected XSS vulnerability requiring user interaction",
                       "{} has an information exposure revealing system details"],
            "Low": ["Version number disclosure in {} reveals software version in HTTP headers",
                    "Missing security headers in {} reduce browser-side protection"],
        }
        sev_dist = {"Critical": 0.12, "High": 0.28, "Medium": 0.38, "Low": 0.22}
        records = []
        c = 1000
        for sev, pct in sev_dist.items():
            for i in range(int(1200 * pct)):
                prod = products[c % len(products)]
                desc = descs[sev][c % len(descs[sev])].format(prod)
                records.append({"cve_id": f"CVE-2024-{c:04d}", "severity": sev,
                                "description": desc, "product": prod})
                c += 1
        with open(synth_path, "w") as f:
            json.dump(records, f, indent=2)
        print(f"[+] Synthetic dataset: {synth_path} ({len(records)} records)")

    # ─── Build ontology using owlready2 ───
    owl_path = os.path.join(data_dir, "cyberonto.owl")
    if not os.path.exists(owl_path):
        print("[*] Building OWL ontology...")
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
            from build_ontology import build_ontology_owlready
            build_ontology_owlready(owl_path)
        except Exception as e:
            print(f"[!] Ontology build failed: {e}")
            sys.exit(1)

    # ─── Load into RDFLib for SPARQL ───
    print("[*] Loading ontology into RDFLib...")
    t0 = time.time()
    graph = Graph()
    graph.parse(owl_path, format="xml")
    load_time = time.time() - t0
    CO = Namespace("http://cyberonto.org/ontology#")
    graph.bind("co", CO)
    print(f"[+] RDF graph ready: {len(graph)} triples (loaded in {load_time:.3f}s)")

    # ─── Execute all 12 CQs with HONEST timing ───
    print("[*] Executing 12 SPARQL competency questions...")
    all_results = {}
    total_query_time = 0.0

    for cq_id, data in SPARQL_QUERIES.items():
        try:
            # Full count (remove LIMIT)
            count_query = data["sparql"].replace("LIMIT 10", "").replace("LIMIT 15", "").replace("LIMIT 20", "")

            t0 = time.time()
            full_count, _ = exec_query(graph, count_query, 1)
            count_time = time.time() - t0

            # Sample results (with LIMIT)
            t0 = time.time()
            _, samples = exec_query(graph, data["sparql"], 10)
            sample_time = time.time() - t0

            query_time = count_time + sample_time
            total_query_time += query_time

            all_results[cq_id] = {
                "category": data["category"],
                "question": data["question"],
                "sparql": data["sparql"],
                "explanation": data["explanation"],
                "actual_count": full_count,
                "execution_time_seconds": round(query_time, 4),
                "results": samples
            }
            print(f"    {cq_id}: {full_count} rows | {query_time:.4f}s")
        except Exception as e:
            print(f"    {cq_id}: ERROR - {str(e)[:80]}")
            all_results[cq_id] = {
                "category": data["category"],
                "question": data["question"],
                "sparql": data["sparql"],
                "explanation": data["explanation"],
                "actual_count": 0,
                "execution_time_seconds": 0.0,
                "error": str(e),
                "results": []
            }

    print(f"\n[*] Total SPARQL execution time: {total_query_time:.4f}s")
    print(f"[*] Average per query: {total_query_time/12:.4f}s")

    # ─── Save JSON ───
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"[+] JSON saved: {output_path}")

    # ─── Save Markdown with HONEST results ───
    md_path = output_path.replace(".json", ".md")
    with open(md_path, "w") as f:
        f.write("# CyberOnto Competency Questions: SPARQL Examples with Actual Results\n\n")
        f.write("**Ontology:** http://cyberonto.org/ontology  \n")
        f.write(f"**Triples:** {len(graph):,}  \n")
        f.write(f"**Total Query Time:** {total_query_time:.4f}s  \n\n")
        f.write("---\n\n")
        for cq_id, data in all_results.items():
            f.write(f"## {cq_id}: {data['question']}\n\n")
            f.write(f"**Category:** {data['category']}  \n")
            f.write(f"**Actual Results:** {data['actual_count']} rows  \n")
            f.write(f"**Execution Time:** {data.get('execution_time_seconds', 0):.4f}s  \n\n")
            f.write(f"{data['explanation']}  \n\n")
            f.write("```sparql\n")
            f.write(data["sparql"])
            f.write("\n```\n\n")
            if data["results"]:
                f.write("### Sample Results\n\n")
                headers = list(data["results"][0].keys())
                f.write("| " + " | ".join(headers) + " |\n")
                f.write("|" + "|".join(["---"] * len(headers)) + "|\n")
                for row in data["results"][:6]:
                    vals = []
                    for h in headers:
                        v = str(row.get(h, ""))
                        if v.startswith("http://"):
                            v = v.split("#")[-1][:50]
                        elif len(v) > 60:
                            v = v[:57] + "..."
                        vals.append(v)
                    f.write("| " + " | ".join(vals) + " |\n")
            f.write("\n---\n\n")
    print(f"[+] Markdown saved: {md_path}")
    return all_results


def generate_sparql_examples(output_path):
    """Legacy entry point: build ontology + execute all queries."""
    return build_and_execute(output_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberOnto CQ SPARQL execution with timing")
    parser.add_argument("--output", default="../results/cq_sparql_examples.json")
    parser.add_argument("--data-dir", default=None)
    args = parser.parse_args()
    build_and_execute(args.output, args.data_dir)
