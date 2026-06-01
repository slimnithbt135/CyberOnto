# CyberOnto Competency Questions: SPARQL Examples

## CQ1: Which vulnerabilities in the dataset have Critical severity and involve remote code execution?

**Category:** Vulnerability Retrieval

**Explanation:** Retrieves all CVE instances classified as Critical whose descriptions contain the phrase 'remote code execution'. This represents the most dangerous vulnerabilities requiring immediate attention.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?vuln ?cveId ?description
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Critical ;
        co:cveId ?cveId ;
        co:description ?description .
  FILTER(CONTAINS(LCASE(STR(?description)), "remote code execution"))
}
ORDER BY ?cveId
```

**Expected result count:** 48 row(s)

---

## CQ2: What is the CVSS base score distribution across all High-severity vulnerabilities?

**Category:** Vulnerability Retrieval

**Explanation:** Aggregates CVSS base scores for High-severity vulnerabilities, revealing the score distribution pattern. High-severity CVEs typically cluster in the 7.0-8.9 range.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?score (COUNT(?vuln) AS ?count)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:High ;
        co:cvssBaseScore ?score .
}
GROUP BY ?score
ORDER BY DESC(?count)
```

**Expected result count:** 5 row(s)

---

## CQ3: Which products are most frequently affected by Medium-severity cross-site scripting vulnerabilities?

**Category:** Vulnerability Retrieval

**Explanation:** Ranks products by frequency of Medium-severity XSS vulnerabilities, enabling security teams to prioritise patching efforts for the most affected products.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 10
```

**Expected result count:** 10 row(s)

---

## CQ4: What CWE classifications are associated with buffer overflow vulnerabilities in the dataset?

**Category:** Vulnerability Retrieval

**Explanation:** Joins CVE records with CWE classifications to identify weakness types associated with buffer overflow descriptions. Expected results include CWE-121 (Stack-based Buffer Overflow) and CWE-122 (Heap-based Buffer Overflow).

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
ORDER BY ?cweId
```

**Expected result count:** 4 row(s)

---

## CQ5: Which ATT&CK techniques are associated with vulnerabilities that have Information Disclosure impact?

**Category:** Cross-Framework Reasoning

**Explanation:** Traverses from CVE instances through attack technique relationships to identify ATT&CK techniques linked to information disclosure vulnerabilities. Demonstrates cross-framework traversal from vulnerability data to adversary tactics.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
ORDER BY ?techniqueId
```

**Expected result count:** 6 row(s)

---

## CQ6: What D3FEND countermeasures map to the attack techniques used by Critical-severity vulnerabilities?

**Category:** Cross-Framework Reasoning

**Explanation:** Performs a two-hop traversal from Critical CVEs through ATT&CK techniques to D3FEND countermeasures. This cross-framework join is a key differentiator of CyberOnto---no single security standard provides this linkage.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
ORDER BY ?counterId
```

**Expected result count:** 8 row(s)

---

## CQ7: Which vulnerabilities bridge specific ATT&CK tactics to D3FEND defensive measures through CWE weaknesses?

**Category:** Cross-Framework Reasoning

**Explanation:** Executes multi-hop reasoning across three frameworks: CWE weaknesses link vulnerabilities to ATT&CK tactics, which map to D3FEND countermeasures. This three-way join demonstrates CyberOnto's unique ability to bridge vulnerability, adversary, and defensive knowledge in a single query.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 20
```

**Expected result count:** 20 row(s)

---

## CQ8: What is the coverage of the ATT&CK tactic 'Initial Access' in the vulnerability dataset?

**Category:** Cross-Framework Reasoning

**Explanation:** Counts vulnerabilities and techniques mapped to the ATT&CK Initial Access tactic, quantifying how much of the dataset relates to the adversary lifecycle phase of gaining an initial foothold.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT (COUNT(DISTINCT ?vuln) AS ?vulnCount)
       (COUNT(DISTINCT ?technique) AS ?techniqueCount)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasAttackTechnique ?technique .
  ?technique co:attckTactic ?tactic .
  ?tactic co:tacticName "Initial Access" .
}
```

**Expected result count:** 2 row(s)

---

## CQ9: Given a vulnerability, what mitigations, detection methods, and security controls are applicable?

**Category:** Threat Intelligence Enrichment

**Explanation:** Retrieves the complete defensive profile for each vulnerability: mitigations (how to fix), detection methods (how to find), and security controls (how to prevent). This triple-enrichment query is essential for security operations centres building comprehensive response plans.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT ?cveId ?mitigation ?detection ?control
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
LIMIT 10
```

**Expected result count:** 10 row(s)

---

## CQ10: Which vulnerabilities share both attack techniques and affected products?

**Category:** Threat Intelligence Enrichment

**Explanation:** Finds vulnerability pairs that share both attack technique and product, identifying clusters of related vulnerabilities. Security analysts use this to assess whether a newly disclosed vulnerability affects products with known vulnerability patterns.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 15
```

**Expected result count:** 15 row(s)

---

## CQ11: What is the complete attack path from a vulnerability to its defensive countermeasures?

**Category:** Threat Intelligence Enrichment

**Explanation:** Traces the complete path from vulnerability description through attack technique and tactic to defensive countermeasure. This path query demonstrates CyberOnto's ability to connect offensive and defensive knowledge in a single traversal.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 20
```

**Expected result count:** 20 row(s)

---

## CQ12: How many vulnerabilities lack associated mitigations in the current knowledge base?

**Category:** Threat Intelligence Enrichment

**Explanation:** Counts vulnerabilities with no mitigation relationship, identifying gaps in the knowledge base that require analyst attention. This gap analysis query helps prioritise knowledge enrichment efforts.

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

SELECT (COUNT(?vuln) AS ?unmitigatedCount)
WHERE {
  ?vuln rdf:type co:CVE .
  OPTIONAL { ?vuln co:hasMitigation ?mit . }
  FILTER(!BOUND(?mit))
}
```

**Expected result count:** 1 row(s)

---

