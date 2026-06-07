# CyberOnto Competency Questions: SPARQL Examples with Actual Results

**Ontology:** http://cyberonto.org/ontology  
**Triples:** 29,181  
**Total Query Time:** 245.7990s  

---

## CQ1: Which vulnerabilities in the dataset have Critical severity and involve remote code execution?

**Category:** Vulnerability Retrieval  
**Actual Results:** 23 rows  
**Execution Time:** 0.4431s  

Retrieves Critical CVEs with CWE-94 weakness containing 'remote code execution'. Uses FILTER(STR()) for safe literal matching.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 10
```

### Sample Results

| cveId | description | cvssScore |
|---|---|---|
| CVE-2024-1053 | A remote code execution vulnerability in OpenSSL enables ... | 9.5 |
| CVE-2024-1125 | A wormable exploit vulnerability in Grafana allows unauth... | 9.5 |
| CVE-2024-1030 | A sandbox escape vulnerability in AWS EC2 allows unauthor... | 9.5 |
| CVE-2024-1034 | A zero-day vulnerability vulnerability in GitLab allows u... | 9.5 |
| CVE-2024-1086 | A kernel privilege escalation vulnerability in Microsoft ... | 9.5 |
| CVE-2024-1062 | A remote code execution vulnerability in Windows Server e... | 9.5 |

---

## CQ2: What is the CVSS base score distribution across all High-severity vulnerabilities?

**Category:** Vulnerability Retrieval  
**Actual Results:** 1 rows  
**Execution Time:** 0.1075s  

Aggregates CVSS base scores via hasCVSS -> CVSS for High-severity vulnerabilities.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
SELECT ?score (COUNT(?vuln) AS ?count)
WHERE {
  ?vuln rdf:type co:CVE ;
        co:hasSeverity co:Severity_High ;
        co:hasCVSS ?cvss .
  ?cvss co:cvssBaseScore ?score .
}
GROUP BY ?score
ORDER BY DESC(?count)
```

### Sample Results

| score | count |
|---|---|
| 8.0 | 336 |

---

## CQ3: Which products are most frequently affected by Medium-severity cross-site scripting vulnerabilities?

**Category:** Vulnerability Retrieval  
**Actual Results:** 21 rows  
**Execution Time:** 0.4017s  

Ranks products by Medium-severity XSS vulnerability frequency.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 10
```

### Sample Results

| product | vulnCount |
|---|---|
| Product_MongoDB | 4 |
| Product_Jenkins | 3 |
| Product_Fortinet_FortiOS | 2 |
| Product_MySQL | 2 |
| Product_OpenSSL | 2 |
| Product_AWS_EC2 | 2 |

---

## CQ4: What CWE classifications are associated with buffer overflow vulnerabilities?

**Category:** Vulnerability Retrieval  
**Actual Results:** 1 rows  
**Execution Time:** 0.5591s  

Joins CVE records with CWE classifications via hasCWE for buffer overflow descriptions.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
ORDER BY ?cweIdVal
```

### Sample Results

| cweName |
|---|
| Buffer Overflow |

---

## CQ5: Which ATT&CK techniques are associated with vulnerabilities that have Information Disclosure impact?

**Category:** Cross-Framework Reasoning  
**Actual Results:** 4 rows  
**Execution Time:** 0.8987s  

Traverses CVEs through hasCWE -> CWE to ATT&CK techniques for Information Disclosure.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
ORDER BY ?techniqueId
```

### Sample Results

| techniqueId | techniqueName |
|---|---|
| T1003 | OS Credential Dumping |
| T1021 | Remote Services |
| T1083 | File and Directory Discovery |
| T1190 | Exploit Public-Facing Application |

---

## CQ6: What D3FEND countermeasures map to the attack techniques used by Critical-severity vulnerabilities?

**Category:** Cross-Framework Reasoning  
**Actual Results:** 4 rows  
**Execution Time:** 0.1229s  

Two-hop traversal: Critical CVEs -> ATT&CK techniques -> D3FEND countermeasures via mitigatedBy.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
ORDER BY ?counterId
```

### Sample Results

| counterId | counterName |
|---|---|
| D3-AC | Account Access Control |
| D3-AL | Application Hardening |
| D3-FE | Filter Enterprise Traffic |
| D3-NS | Network Segmentation |

---

## CQ7: Which vulnerabilities bridge specific ATT&CK tactics to D3FEND defensive measures through CWE weaknesses?

**Category:** Cross-Framework Reasoning  
**Actual Results:** 2400 rows  
**Execution Time:** 1.7148s  

Multi-hop reasoning across three frameworks: hasCWE -> ATT&CK tactics -> D3FEND.  

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

### Sample Results

| vuln | cveId | cweName | tacticName | counterName |
|---|---|---|---|---|
| cve_CVE_2024_1000 | CVE-2024-1000 | Code Injection | Initial Access | Application Hardening |
| cve_CVE_2024_1000 | CVE-2024-1000 | Code Injection | Initial Access | Filter Enterprise Traffic |
| cve_CVE_2024_1001 | CVE-2024-1001 | SQL Injection | Initial Access | Application Hardening |
| cve_CVE_2024_1001 | CVE-2024-1001 | SQL Injection | Initial Access | Filter Enterprise Traffic |
| cve_CVE_2024_1002 | CVE-2024-1002 | Code Injection | Initial Access | Application Hardening |
| cve_CVE_2024_1002 | CVE-2024-1002 | Code Injection | Initial Access | Filter Enterprise Traffic |

---

## CQ8: What is the coverage of the ATT&CK tactic 'Initial Access' in the vulnerability dataset?

**Category:** Cross-Framework Reasoning  
**Actual Results:** 1 rows  
**Execution Time:** 0.0266s  

Counts vulnerabilities and techniques mapped to Initial Access tactic.  

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

### Sample Results

| vulnCount | techniqueCount |
|---|---|
| 0 | 0 |

---

## CQ9: Given a vulnerability, what mitigations, detection methods, and security controls are applicable?

**Category:** Threat Intelligence Enrichment  
**Actual Results:** 1200 rows  
**Execution Time:** 1.0243s  

Retrieves defensive profile for vulnerabilities using hasMitigation, hasDetectionMethod, and hasSecurityControl.  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 10
```

### Sample Results

| cveId | mitigation | detection | control |
|---|---|---|---|
| CVE-2024-1000 | Immediate patching required. Isolate affected systems. De... | Vulnerability Scanning | Output Encoding |
| CVE-2024-1001 | Immediate patching required. Isolate affected systems. De... | Network Traffic Monitoring | Input Validation |
| CVE-2024-1002 | Immediate patching required. Isolate affected systems. De... | Vulnerability Scanning | Encryption in Transit |
| CVE-2024-1003 | Immediate patching required. Isolate affected systems. De... | Vulnerability Scanning | Input Validation |
| CVE-2024-1004 | Immediate patching required. Isolate affected systems. De... | Network Traffic Monitoring | Input Validation |
| CVE-2024-1005 | Immediate patching required. Isolate affected systems. De... | Vulnerability Scanning | Input Validation |

---

## CQ10: Which vulnerabilities share both attack techniques and affected products?

**Category:** Threat Intelligence Enrichment  
**Actual Results:** 20126 rows  
**Execution Time:** 238.3639s  

Finds vulnerability pairs sharing both attack technique and product (self-join).  

```sparql
PREFIX co: <http://cyberonto.org/ontology#>
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
LIMIT 15
```

### Sample Results

| cve1 | cve2 | sharedTechnique | prod |
|---|---|---|---|
| CVE-2024-1693 | CVE-2024-1811 | Command and Scripting Interpreter | Product_AWS_EC2 |
| CVE-2024-1735 | CVE-2024-1925 | Exploit Public-Facing Application | Product_AWS_EC2 |
| CVE-2024-1735 | CVE-2024-2124 | Exploit Public-Facing Application | Product_AWS_EC2 |
| CVE-2024-1735 | CVE-2024-1959 | Exploit Public-Facing Application | Product_AWS_EC2 |
| CVE-2024-1735 | CVE-2024-1939 | Exploit Public-Facing Application | Product_AWS_EC2 |
| CVE-2024-1735 | CVE-2024-1969 | Exploit Public-Facing Application | Product_AWS_EC2 |

---

## CQ11: What is the complete attack path from a vulnerability to its defensive countermeasures?

**Category:** Threat Intelligence Enrichment  
**Actual Results:** 2400 rows  
**Execution Time:** 1.7093s  

Traces complete path: vulnerability -> technique -> tactic -> D3FEND countermeasure.  

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

### Sample Results

| cveId | vulnDesc | techniqueName | tacticName | counterName |
|---|---|---|---|---|
| CVE-2024-1000 | A sandbox escape vulnerability in Grafana allows remote a... | Exploit Public-Facing Application | Initial Access | Application Hardening |
| CVE-2024-1000 | A sandbox escape vulnerability in Grafana allows remote a... | Exploit Public-Facing Application | Initial Access | Filter Enterprise Traffic |
| CVE-2024-1001 | A authentication bypass vulnerability in PostgreSQL enabl... | Exploit Public-Facing Application | Initial Access | Application Hardening |
| CVE-2024-1001 | A authentication bypass vulnerability in PostgreSQL enabl... | Exploit Public-Facing Application | Initial Access | Filter Enterprise Traffic |
| CVE-2024-1002 | A kernel privilege escalation vulnerability in OpenSSL al... | Exploit Public-Facing Application | Initial Access | Application Hardening |
| CVE-2024-1002 | A kernel privilege escalation vulnerability in OpenSSL al... | Exploit Public-Facing Application | Initial Access | Filter Enterprise Traffic |

---

## CQ12: How many vulnerabilities lack associated mitigations in the current knowledge base?

**Category:** Threat Intelligence Enrichment  
**Actual Results:** 1 rows  
**Execution Time:** 0.4272s  

Counts vulnerabilities with no mitigation relationship (gap analysis).  

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

### Sample Results

| unmitigatedCount |
|---|
| 0 |

---

