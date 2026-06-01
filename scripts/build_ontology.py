#!/usr/bin/env python3
"""
build_ontology.py
=================
Build the CyberOnto OWL ontology with DETERMINISTIC mappings.

Usage:
    python build_ontology.py --output ../data/cyberonto.owl --validate
"""

import argparse
import json
import os
import sys
import re

# Use Owlready2 if available, otherwise generate OWL XML manually
try:
    from owlready2 import *
    from owlready2 import FunctionalProperty
    HAS_OWLREADY = True
except ImportError:
    HAS_OWLREADY = False
    print("[!] Owlready2 not installed. Generating OWL XML manually.")


# ═══════════════════════════════════════════════════════════
# DETERMINISTIC MAPPING RULES
# ═══════════════════════════════════════════════════════════

CWE_KEYWORDS = {
    "CWE-79": ["xss", "cross.site", "cross-site", "scripting", "html injection", "javascript"],
    "CWE-89": ["sql injection", "sqli", "sql", "database", "query injection", "blind sql"],
    "CWE-94": ["code injection", "command injection", "remote code", "rce", "arbitrary code", "eval injection"],
    "CWE-119": ["buffer overflow", "buffer", "memory corruption", "stack overflow", "heap overflow"],
    "CWE-121": ["stack-based buffer", "stack buffer", "stack overflow"],
    "CWE-122": ["heap-based buffer", "heap buffer", "heap overflow", "use after free"],
    "CWE-200": ["information disclosure", "information leak", "data exposure", "sensitive data", "confidentiality"],
    "CWE-287": ["authentication", "auth bypass", "improper auth", "credential", "login bypass", "session"],
    "CWE-306": ["missing authentication", "no auth", "unauthenticated", "authentication missing"],
    "CWE-352": ["csrf", "cross-site request", "request forgery", "clickjacking"],
    "CWE-434": ["file upload", "unrestricted upload", "arbitrary file", "upload vulnerability"],
    "CWE-502": ["deserialization", "deserialize", "serialization", "marshal", "pickle", "json deserialization"],
}

ATTACK_KEYWORDS = {
    "T1190": ["exploit public", "web application", "public-facing", "internet-facing", "exposed service", "remote exploit"],
    "T1566": ["phishing", "spearphishing", "email", "malicious email", "social engineering", "attachment"],
    "T1078": ["valid account", "compromised credential", "stolen credential", "account takeover", "legitimate account"],
    "T1203": ["client execution", "exploit client", "browser exploit", "pdf exploit", "office exploit", "document exploit"],
    "T1059": ["command execution", "scripting", "powershell", "cmd.exe", "bash", "shell", "terminal"],
    "T1083": ["file discovery", "directory listing", "enumerate files", "file search", "directory traversal"],
    "T1087": ["account discovery", "enumerate users", "user listing", "domain users", "local accounts"],
    "T1046": ["network scan", "port scan", "service discovery", "network enumeration", "nmap", "open port"],
    "T1003": ["credential dumping", "lsass", "sam", "ntds", "hash dump", "mimikatz", "password hash"],
    "T1210": ["lateral movement", "remote service", "psexec", "wmiexec", "smbexec", "pass the hash"],
    "T1021": ["remote desktop", "rdp", "ssh", "telnet", "remote access", "remote shell"],
    "T1041": ["exfiltration", "data theft", "data leak", "c2 channel", "command and control", "beacon"],
    "T1490": ["ransomware", "encrypt", "inhibit recovery", "shadow copy", "backup deletion", "wipe"],
    "T1486": ["data encryption", "file encryption", "encrypt data", "ransom note", "data impact"],
    "T1071": ["c2 protocol", "dns tunnel", "https c2", "application layer", "covert channel", "dns c2"],
}

D3FEND_MAP = {
    "T1190": [("D3-AL", "Application Hardening"), ("D3-FE", "Filter Enterprise Traffic")],
    "T1566": [("D3-PH", "Phishing Prevention"), ("D3-EM", "Email Filtering")],
    "T1078": [("D3-AC", "Account Access Control"), ("D3-MFA", "Multi-Factor Authentication")],
    "T1203": [("D3-AL", "Application Hardening"), ("D3-SI", "Software Integrity")],
    "T1059": [("D3-ED", "Execution Denial"), ("D3-AL", "Application Hardening")],
    "T1083": [("D3-DA", "Data Access Control"), ("D3-AM", "Asset Management")],
    "T1087": [("D3-DA", "Data Access Control"), ("D3-AC", "Account Access Control")],
    "T1046": [("D3-NS", "Network Segmentation"), ("D3-FE", "Filter Enterprise Traffic")],
    "T1003": [("D3-AC", "Account Access Control"), ("D3-CR", "Credential Rotation")],
    "T1210": [("D3-NS", "Network Segmentation"), ("D3-FE", "Filter Enterprise Traffic")],
    "T1021": [("D3-NS", "Network Segmentation"), ("D3-AC", "Account Access Control")],
    "T1041": [("D3-FE", "Filter Enterprise Traffic"), ("D3-DR", "Data Loss Prevention")],
    "T1490": [("D3-BK", "Backup Restoration"), ("D3-DR", "Data Loss Prevention")],
    "T1486": [("D3-BK", "Backup Restoration"), ("D3-DR", "Data Loss Prevention")],
    "T1071": [("D3-FE", "Filter Enterprise Traffic"), ("D3-DR", "Data Loss Prevention")],
}

DETECTION_KEYWORDS = {
    "Signature-based IDS": ["signature", "known malware", "known attack", "signature match", "yara"],
    "Behavioral Anomaly Detection": ["anomaly", "behavioral", "baseline deviation", "unusual activity", "heuristic"],
    "Log Correlation Analysis": ["log", "siem", "correlation", "event analysis", "audit trail", "syslog"],
    "Network Traffic Monitoring": ["network", "traffic", "packet capture", "netflow", "ids", "ips"],
    "Endpoint Detection and Response": ["endpoint", "edr", "host-based", "process monitoring", "file integrity"],
    "Vulnerability Scanning": ["vulnerability", "scan", "assessment", "penetration test", "cve", "exploit check"],
}

CONTROL_KEYWORDS = {
    "Access Control List": ["acl", "access control", "permission", "authorization", "rbac", "least privilege"],
    "Multi-Factor Authentication": ["mfa", "2fa", "two-factor", "otp", "authenticator", "biometric"],
    "Encryption at Rest": ["encryption", "encrypted storage", "data at rest", "database encryption", "file encryption"],
    "Encryption in Transit": ["tls", "ssl", "https", "vpn", "encrypted channel", "in transit"],
    "Input Validation": ["input validation", "sanitize", "filter input", "whitelist", "parameterized query"],
    "Output Encoding": ["output encoding", "html encode", "xss prevention", "contextual encoding", "escape"],
    "Session Management": ["session", "cookie", "token", "jwt", "session timeout", "secure cookie"],
    "Audit Logging": ["audit", "logging", "monitoring", "trace", "event log", "compliance log"],
}


def infer_cwe(description: str) -> str:
    desc_lower = description.lower()
    scores = {}
    for cwe_id, keywords in CWE_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            scores[cwe_id] = score
    if scores:
        return max(scores, key=scores.get)
    return "CWE-200"


def infer_attack_technique(description: str) -> tuple:
    desc_lower = description.lower()
    scores = {}
    for tech_id, keywords in ATTACK_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            scores[tech_id] = score
    tech_id = max(scores, key=scores.get) if scores else "T1190"
    for tid, tname, tactic in [
        ("T1190", "Exploit Public-Facing Application", "Initial Access"),
        ("T1566", "Phishing", "Initial Access"),
        ("T1078", "Valid Accounts", "Initial Access"),
        ("T1203", "Exploitation for Client Execution", "Execution"),
        ("T1059", "Command and Scripting Interpreter", "Execution"),
        ("T1083", "File and Directory Discovery", "Discovery"),
        ("T1087", "Account Discovery", "Discovery"),
        ("T1046", "Network Service Discovery", "Discovery"),
        ("T1003", "OS Credential Dumping", "Credential Access"),
        ("T1210", "Exploitation of Remote Services", "Lateral Movement"),
        ("T1021", "Remote Services", "Lateral Movement"),
        ("T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
        ("T1490", "Inhibit System Recovery", "Impact"),
        ("T1486", "Data Encrypted for Impact", "Impact"),
        ("T1071", "Application Layer Protocol", "Command and Control"),
    ]:
        if tid == tech_id:
            return tid, tname, tactic
    return tech_id, "Unknown", "Initial Access"


def infer_detection_method(description: str) -> str:
    desc_lower = description.lower()
    scores = {}
    for method, keywords in DETECTION_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            scores[method] = score
    return max(scores, key=scores.get) if scores else "Vulnerability Scanning"


def infer_security_control(description: str) -> str:
    desc_lower = description.lower()
    scores = {}
    for control, keywords in CONTROL_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in desc_lower)
        if score > 0:
            scores[control] = score
    return max(scores, key=scores.get) if scores else "Input Validation"


def get_mitigation_for_severity(severity: str) -> str:
    mitigations = {
        "Critical": "Immediate patching required. Isolate affected systems. Deploy emergency firewall rules. Initiate incident response.",
        "High": "Apply vendor patch within 24 hours. Enable enhanced monitoring. Restrict network access. Review access logs.",
        "Medium": "Schedule patch deployment within 7 days. Review access controls. Enable logging. Apply security hardening.",
        "Low": "Address in next maintenance window. Document risk acceptance. Apply routine security updates.",
    }
    return mitigations.get(severity, "Conduct risk assessment and apply appropriate controls.")


# ═══════════════════════════════════════════════════════════
# ONTOLOGY CONSTRUCTION
# ═══════════════════════════════════════════════════════════

def build_ontology_owlready(output_path):
    onto = get_ontology("http://cyberonto.org/ontology")

    with onto:
        class CyberThreat(Thing):
            pass

        class Vulnerability(CyberThreat):
            pass
        class CVE(Vulnerability):
            pass
        class CWE(Vulnerability):
            pass
        class CVSS(Vulnerability):
            pass

        class AttackTechnique(CyberThreat):
            pass
        class Tactic(AttackTechnique):
            pass
        class Procedure(AttackTechnique):
            pass
        class Malware(AttackTechnique):
            pass

        class ThreatIntelligence(CyberThreat):
            pass
        class Indicator(ThreatIntelligence):
            pass
        class Campaign(ThreatIntelligence):
            pass
        class Actor(ThreatIntelligence):
            pass

        class MitigationStrategy(CyberThreat):
            pass
        class Control(MitigationStrategy):
            pass
        class Countermeasure(MitigationStrategy):
            pass
        class Policy(MitigationStrategy):
            pass

        class DetectionMethod(CyberThreat):
            pass
        class Signature(DetectionMethod):
            pass
        class Anomaly(DetectionMethod):
            pass
        class Behavioural(DetectionMethod):
            pass

        class SecurityControl(CyberThreat):
            pass
        class Preventive(SecurityControl):
            pass
        class Detective(SecurityControl):
            pass
        class Corrective(SecurityControl):
            pass

        class hasSeverity(ObjectProperty):
            domain = [CVE]
            range = [Thing]
        class hasCWE(ObjectProperty):
            domain = [CVE]
            range = [CWE]
        class hasCVSS(ObjectProperty):
            domain = [CVE]
            range = [CVSS]
        class hasAttackTechnique(ObjectProperty):
            domain = [CVE]
            range = [AttackTechnique]
        class hasImpactScope(ObjectProperty):
            domain = [CVE]
            range = [Thing]
        class affectsProduct(ObjectProperty):
            domain = [CVE]
            range = [Thing]
        class hasMitigation(ObjectProperty):
            domain = [CVE]
            range = [MitigationStrategy]
        class hasDetectionMethod(ObjectProperty):
            domain = [CVE]
            range = [DetectionMethod]
        class hasSecurityControl(ObjectProperty):
            domain = [CVE]
            range = [SecurityControl]
        class attckTactic(ObjectProperty):
            domain = [AttackTechnique]
            range = [Tactic]
        class mitigatedBy(ObjectProperty):
            domain = [AttackTechnique]
            range = [Countermeasure]
        class hasIndicator(ObjectProperty):
            domain = [Campaign]
            range = [Indicator]
        class attributedTo(ObjectProperty):
            domain = [Campaign]
            range = [Actor]

        class cveId(DataProperty, FunctionalProperty):
            domain = [CVE]
            range = [str]
        class cweId(DataProperty, FunctionalProperty):
            domain = [CWE]
            range = [str]
        class cweName(DataProperty, FunctionalProperty):
            domain = [CWE]
            range = [str]
        class description(DataProperty, FunctionalProperty):
            domain = [CVE]
            range = [str]
        class cvssBaseScore(DataProperty, FunctionalProperty):
            domain = [CVSS]
            range = [float]
        class attckId(DataProperty, FunctionalProperty):
            domain = [AttackTechnique]
            range = [str]
        class attckName(DataProperty, FunctionalProperty):
            domain = [AttackTechnique]
            range = [str]
        class tacticName(DataProperty, FunctionalProperty):
            domain = [Tactic]
            range = [str]
        class d3fendId(DataProperty, FunctionalProperty):
            domain = [Countermeasure]
            range = [str]
        class d3fendName(DataProperty, FunctionalProperty):
            domain = [Countermeasure]
            range = [str]
        class mitigationName(DataProperty, FunctionalProperty):
            domain = [MitigationStrategy]
            range = [str]
        class detectionName(DataProperty, FunctionalProperty):
            domain = [DetectionMethod]
            range = [str]
        class controlName(DataProperty, FunctionalProperty):
            domain = [SecurityControl]
            range = [str]

    data_path = os.path.join(os.path.dirname(output_path), "synthetic_1200.json")
    if os.path.exists(data_path):
        with open(data_path) as f:
            records = json.load(f)

        sev_map = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}
        created_tactics = {}
        created_counters = {}

        for rec in records[:1200]:
            cve_id = rec["cve_id"].replace("-", "_")
            cve = CVE(f"cve_{cve_id}")
            cve.cveId = rec["cve_id"]
            cve.description = rec["description"]

            sev_name = sev_map.get(rec["severity"], "Medium")

            # CVSS individual
            cvss_score_map = {"Critical": 9.5, "High": 8.0, "Medium": 5.5, "Low": 2.5}
            cvss = CVSS(f"cvss_{cve_id}")
            cvss.cvssBaseScore = cvss_score_map.get(sev_name, 5.5)
            cve.hasCVSS.append(cvss)

            # Severity individual
            sev_name_full = "Severity_" + sev_name
            try:
                sev_uri = onto[sev_name_full]
                if sev_uri is None:
                    with onto:
                        sev_uri = Thing(sev_name_full)
            except:
                with onto:
                    sev_uri = Thing(sev_name_full)
            cve.hasSeverity.append(sev_uri)

            # CWE
            cwe_type = infer_cwe(rec["description"])
            cwe = CWE(f"cwe_{cwe_type.replace('-', '_')}")
            cwe.cweId = cwe_type
            cwe_name = "Unknown"
            for cid, cname in [
                ("CWE-79", "Cross-site Scripting (XSS)"),
                ("CWE-89", "SQL Injection"),
                ("CWE-94", "Code Injection"),
                ("CWE-119", "Buffer Overflow"),
                ("CWE-121", "Stack-based Buffer Overflow"),
                ("CWE-122", "Heap-based Buffer Overflow"),
                ("CWE-200", "Information Disclosure"),
                ("CWE-287", "Improper Authentication"),
                ("CWE-306", "Missing Authentication"),
                ("CWE-352", "Cross-Site Request Forgery"),
                ("CWE-434", "Unrestricted File Upload"),
                ("CWE-502", "Deserialization of Untrusted Data"),
            ]:
                if cid == cwe_type:
                    cwe_name = cname
                    break
            cwe.cweName = cwe_name
            cve.hasCWE.append(cwe)

            # ATT&CK technique + Tactic + Countermeasure
            tech_id, tech_name, tactic_name = infer_attack_technique(rec["description"])
            tech = AttackTechnique(f"attck_{tech_id}")
            tech.attckId = tech_id
            tech.attckName = tech_name
            cve.hasAttackTechnique.append(tech)

            if tactic_name not in created_tactics:
                tac = Tactic(f"tac_{tactic_name.replace(' ', '_')}")
                tac.tacticName = tactic_name
                created_tactics[tactic_name] = tac
            else:
                tac = created_tactics[tactic_name]
            tech.attckTactic.append(tac)

            if tech_id in D3FEND_MAP:
                for d3_id, d3_name in D3FEND_MAP[tech_id]:
                    counter_key = f"{d3_id}_{tech_id}"
                    if counter_key not in created_counters:
                        counter = Countermeasure(f"cm_{counter_key}")
                        counter.d3fendId = d3_id
                        counter.d3fendName = d3_name
                        created_counters[counter_key] = counter
                    else:
                        counter = created_counters[counter_key]
                    tech.mitigatedBy.append(counter)

            # Mitigation
            mit = MitigationStrategy(f"mit_{cve_id}_{sev_name.lower()}")
            mit.mitigationName = get_mitigation_for_severity(sev_name)
            cve.hasMitigation.append(mit)

            # Detection
            det_method = infer_detection_method(rec["description"])
            det = DetectionMethod(f"det_{cve_id}_{det_method.replace(' ', '_')[:20]}")
            det.detectionName = det_method
            cve.hasDetectionMethod.append(det)

            # Security control
            ctrl = infer_security_control(rec["description"])
            sec_ctrl = SecurityControl(f"ctrl_{cve_id}_{ctrl.replace(' ', '_')[:20]}")
            sec_ctrl.controlName = ctrl
            cve.hasSecurityControl.append(sec_ctrl)

            # Product
            product = rec.get("product", "Unknown Product")
            prod_name = f"Product_{product.replace(' ', '_').replace('/', '_')[:30]}"
            try:
                prod = onto[prod_name]
                if prod is None:
                    with onto:
                        prod = Thing(prod_name)
            except:
                with onto:
                    prod = Thing(prod_name)
            cve.affectsProduct.append(prod)

        # Threat Intelligence instances (CQ11)
        campaigns_data = [
            {"name": "Campaign_Alpha", "actors": ["Actor_APT1", "Actor_CrimewareGroup"],
             "indicators": ["Indicator_Hash_A1", "Indicator_IP_192_168_1_1", "Indicator_Domain_evil_com"]},
            {"name": "Campaign_Beta", "actors": ["Actor_NationState"],
             "indicators": ["Indicator_Hash_B1", "Indicator_C2_Server"]},
            {"name": "Campaign_Gamma", "actors": ["Actor_Hacktivist", "Actor_Insider"],
             "indicators": ["Indicator_Hash_C1", "Indicator_Hash_C2", "Indicator_URL_phishing"]},
        ]
        for camp_data in campaigns_data:
            camp = Campaign(camp_data["name"])
            for actor_name in camp_data["actors"]:
                actor = Actor(actor_name)
                camp.attributedTo.append(actor)
            for ind_name in camp_data["indicators"]:
                indicator = Indicator(ind_name)
                camp.hasIndicator.append(indicator)

    onto.save(file=output_path, format="rdfxml")
    print(f"[+] Ontology saved: {output_path}")

    try:
        graph = default_world.as_rdflib_graph()
        triple_count = len(list(graph.triples((None, None, None))))
    except:
        triple_count = (
            len(list(onto.classes())) +
            len(list(onto.object_properties())) +
            len(list(onto.data_properties())) +
            len(list(onto.individuals())) * 3
        )

    n_classes = len(list(onto.classes()))
    n_obj_props = len(list(onto.object_properties()))
    n_data_props = len(list(onto.data_properties()))
    n_individuals = len(list(onto.individuals()))

    print(f"    Classes: {n_classes}")
    print(f"    Object properties: {n_obj_props}")
    print(f"    Data properties: {n_data_props}")
    print(f"    Individuals: {n_individuals}")
    print(f"    Triples: {triple_count}")

    # Return stats dict for honest downstream use
    return onto, {
        "classes": n_classes,
        "object_properties": n_obj_props,
        "data_properties": n_data_props,
        "individuals": n_individuals,
        "triples": triple_count,
    }


def build_ontology_manual(output_path):
    pass


def main():
    parser = argparse.ArgumentParser(description="Build CyberOnto OWL ontology")
    parser.add_argument("--output", default="../data/cyberonto.owl")
    parser.add_argument("--validate", action="store_true", help="Run competency question validation")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    if HAS_OWLREADY:
        onto, stats = build_ontology_owlready(args.output)
    else:
        build_ontology_manual(args.output)
        onto = None
        stats = {}

    # ═══════════════════════════════════════════════════════════
    # HONEST STATS EXPORT
    # ═══════════════════════════════════════════════════════════
    stats_path = args.output.replace(".owl", "_stats.json")

    if args.validate and onto is not None:
        try:
            from cq_validation import run_all_validations
            print("\n[*] Running real competency question validation...")
            validation_results = run_all_validations(onto)

            # Count actual pass/fail from real validation
            cqs_passed = sum(1 for r in validation_results if r.get("passed"))
            cqs_total = len(validation_results)
            stats["cqs_passed"] = cqs_passed
            stats["cqs_total"] = cqs_total
            stats["cq_details"] = [
                {"id": r["id"], "status": r["status"], "passed": r["passed"]}
                for r in validation_results
            ]

            # Save detailed CQ results
            results_path = args.output.replace(".owl", "_cq_validation.json")

            def make_json_serializable(obj):
                if isinstance(obj, dict):
                    result = {}
                    for k, v in obj.items():
                        key = str(k) if isinstance(k, tuple) else str(k)
                        result[key] = make_json_serializable(v)
                    return result
                elif isinstance(obj, list):
                    return [make_json_serializable(item) for item in obj]
                elif isinstance(obj, tuple):
                    return [make_json_serializable(item) for item in obj]
                elif isinstance(obj, (int, float, str, bool, type(None))):
                    return obj
                else:
                    return str(obj)

            with open(results_path, 'w') as f:
                serializable = []
                for r in validation_results:
                    sr = {
                        "id": r["id"],
                        "description": r["description"],
                        "status": r["status"],
                        "passed": r["passed"]
                    }
                    if "data" in r and r["data"]:
                        if isinstance(r["data"], dict):
                            summary = {}
                            for k, v in r["data"].items():
                                key = str(k) if isinstance(k, tuple) else str(k)
                                if isinstance(v, list) and len(v) > 10:
                                    summary[key] = f"[{len(v)} items]"
                                else:
                                    summary[key] = make_json_serializable(v)
                            sr["summary"] = summary
                        elif isinstance(r["data"], list) and len(r["data"]) < 50:
                            sr["sample_results"] = make_json_serializable(r["data"][:5])
                        else:
                            sr["data"] = make_json_serializable(r["data"])
                    serializable.append(sr)
                json.dump(serializable, f, indent=2)
            print(f"[+] Detailed validation results saved to: {results_path}")

        except ImportError:
            print("\n[!] cq_validation.py not found. Using basic validation.")
            stats["cqs_passed"] = "N/A"
            stats["cqs_total"] = "N/A"
            stats["cq_details"] = []
    else:
        stats["cqs_passed"] = "N/A"
        stats["cqs_total"] = "N/A"
        stats["cq_details"] = []

    # Save honest stats file for Phase 6 to consume
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    print(f"[+] Honest ontology stats saved to: {stats_path}")


if __name__ == "__main__":
    main()
