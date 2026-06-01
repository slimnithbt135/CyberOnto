
# ═══════════════════════════════════════════════════════════
# REAL COMPETENCY QUESTION VALIDATION
# ═══════════════════════════════════════════════════════════

def validate_cq1_critical_rce(onto):
    """
    CQ1: Can we retrieve Critical RCE vulnerabilities?
    Query: Find CVEs with Critical severity AND RCE-related attack technique
    """
    results = []
    for cve in onto.CVE.instances():
        # Check severity
        has_critical = False
        if cve.hasSeverity:
            for sev in cve.hasSeverity:
                if "Critical" in str(sev):
                    has_critical = True
                    break

        # Check RCE-related technique (T1190=Exploit Public-Facing, T1203=Client Execution)
        has_rce = False
        if cve.hasAttackTechnique:
            for tech in cve.hasAttackTechnique:
                if hasattr(tech, 'attckId') and tech.attckId:
                    tech_id = str(tech.attckId)
                    if any(t in tech_id for t in ["T1190", "T1203", "T1059", "T1210"]):
                        has_rce = True
                        break

        if has_critical and has_rce:
            results.append(str(cve.cveId) if hasattr(cve, 'cveId') else str(cve))

    passed = len(results) > 0
    return passed, results


def validate_cq2_cvss_distribution(onto):
    """
    CQ2: Can we get CVSS score distribution?
    Query: Retrieve all CVSS scores and categorize by severity
    """
    scores = []
    for cvss in onto.CVSS.instances():
        if hasattr(cvss, 'cvssBaseScore') and cvss.cvssBaseScore:
            try:
                score = float(cvss.cvssBaseScore)
                scores.append(score)
            except:
                pass

    # Categorize
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for score in scores:
        if score >= 9.0:
            distribution["Critical"] += 1
        elif score >= 7.0:
            distribution["High"] += 1
        elif score >= 4.0:
            distribution["Medium"] += 1
        else:
            distribution["Low"] += 1

    passed = len(scores) > 0
    return passed, {"scores": scores, "distribution": distribution}


def validate_cq3_xss_ranking(onto):
    """
    CQ3: Can we rank products by XSS vulnerability count?
    Query: Find CVEs linked to CWE-79 (XSS) and group by affected product
    """
    product_counts = {}
    for cve in onto.CVE.instances():
        # Check if linked to CWE-79
        is_xss = False
        if cve.hasCWE:
            for cwe in cve.hasCWE:
                if hasattr(cwe, 'cweId') and cwe.cweId:
                    if "CWE-79" in str(cwe.cweId):
                        is_xss = True
                        break

        if is_xss:
            # Get affected product
            if cve.affectsProduct:
                for prod in cve.affectsProduct:
                    prod_name = str(prod).split("#")[-1] if "#" in str(prod) else str(prod)
                    product_counts[prod_name] = product_counts.get(prod_name, 0) + 1

    # Sort by count descending
    ranked = sorted(product_counts.items(), key=lambda x: x[1], reverse=True)
    passed = len(ranked) > 0
    return passed, ranked


def validate_cq4_cwe_classification(onto):
    """
    CQ4: Can we classify CVEs by CWE type?
    Query: Group CVEs by their CWE classification
    """
    cwe_groups = {}
    for cve in onto.CVE.instances():
        if cve.hasCWE:
            for cwe in cve.hasCWE:
                cwe_id = str(cwe.cweId) if hasattr(cwe, 'cweId') and cwe.cweId else str(cwe)
                cwe_name = str(cwe.cweName) if hasattr(cwe, 'cweName') and cwe.cweName else "Unknown"
                key = f"{cwe_id}: {cwe_name}"
                if key not in cwe_groups:
                    cwe_groups[key] = []
                cve_id = str(cve.cveId) if hasattr(cve, 'cveId') else str(cve)
                cwe_groups[key].append(cve_id)

    passed = len(cwe_groups) > 0
    return passed, cwe_groups


def validate_cq5_attack_technique_mapping(onto):
    """
    CQ5: Can we map CVEs to ATT&CK techniques?
    Query: Verify that CVEs have attack technique links
    """
    mapped = 0
    unmapped = 0
    technique_counts = {}

    for cve in onto.CVE.instances():
        if cve.hasAttackTechnique:
            mapped += 1
            for tech in cve.hasAttackTechnique:
                tech_id = str(tech.attckId) if hasattr(tech, 'attckId') and tech.attckId else str(tech)
                technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1
        else:
            unmapped += 1

    total = mapped + unmapped
    coverage = (mapped / total * 100) if total > 0 else 0
    passed = mapped > 0

    return passed, {
        "mapped": mapped,
        "unmapped": unmapped,
        "coverage": round(coverage, 2),
        "technique_counts": technique_counts
    }


def validate_cq6_d3fend_mapping(onto):
    """
    CQ6: Can we map attack techniques to D3FEND countermeasures?
    Query: Verify mitigatedBy links between AttackTechnique and Countermeasure
    """
    technique_counter_pairs = []
    for tech in onto.AttackTechnique.instances():
        if hasattr(tech, 'mitigatedBy') and tech.mitigatedBy:
            for counter in tech.mitigatedBy:
                tech_id = str(tech.attckId) if hasattr(tech, 'attckId') else str(tech)
                counter_id = str(counter.d3fendId) if hasattr(counter, 'd3fendId') else str(counter)
                technique_counter_pairs.append((tech_id, counter_id))

    passed = len(technique_counter_pairs) > 0
    return passed, technique_counter_pairs


def validate_cq7_multihop_reasoning(onto):
    """
    CQ7: Can we perform multi-hop reasoning (CVE → Technique → Tactic → Countermeasure)?
    Query: Trace paths from CVE through technique to tactic and countermeasure
    """
    paths = []
    for cve in onto.CVE.instances():
        if cve.hasAttackTechnique:
            for tech in cve.hasAttackTechnique:
                # Technique → Tactic
                tactics = []
                if hasattr(tech, 'attckTactic') and tech.attckTactic:
                    for tac in tech.attckTactic:
                        tac_name = str(tac.tacticName) if hasattr(tac, 'tacticName') else str(tac)
                        tactics.append(tac_name)

                # Technique → Countermeasure
                counters = []
                if hasattr(tech, 'mitigatedBy') and tech.mitigatedBy:
                    for counter in tech.mitigatedBy:
                        counter_name = str(counter.d3fendName) if hasattr(counter, 'd3fendName') else str(counter)
                        counters.append(counter_name)

                if tactics or counters:
                    cve_id = str(cve.cveId) if hasattr(cve, 'cveId') else str(cve)
                    tech_id = str(tech.attckId) if hasattr(tech, 'attckId') else str(tech)
                    paths.append({
                        "cve": cve_id,
                        "technique": tech_id,
                        "tactics": tactics,
                        "countermeasures": counters
                    })

    passed = len(paths) > 0
    return passed, paths


def validate_cq8_initial_access_coverage(onto):
    """
    CQ8: What percentage of techniques cover Initial Access tactic?
    Query: Count techniques linked to Initial Access tactic
    """
    initial_access_techniques = []
    for tactic in onto.Tactic.instances():
        tac_name = str(tactic.tacticName) if hasattr(tactic, 'tacticName') else str(tactic)
        if "Initial Access" in tac_name:
            # Find techniques linked to this tactic
            for tech in onto.AttackTechnique.instances():
                if hasattr(tech, 'attckTactic') and tech.attckTactic:
                    for linked_tac in tech.attckTactic:
                        if linked_tac == tactic:
                            tech_id = str(tech.attckId) if hasattr(tech, 'attckId') else str(tech)
                            initial_access_techniques.append(tech_id)

    total_techniques = len(list(onto.AttackTechnique.instances()))
    coverage = (len(initial_access_techniques) / total_techniques * 100) if total_techniques > 0 else 0
    passed = len(initial_access_techniques) > 0

    return passed, {
        "initial_access_count": len(initial_access_techniques),
        "total_techniques": total_techniques,
        "coverage": round(coverage, 2)
    }


def validate_cq9_defensive_profile(onto):
    """
    CQ9: Can we build a complete defensive profile for a CVE?
    Query: For a CVE, retrieve all linked mitigations, detection methods, and security controls
    """
    profiles = []
    for cve in onto.CVE.instances():
        cve_id = str(cve.cveId) if hasattr(cve, 'cveId') else str(cve)

        mitigations = []
        if cve.hasMitigation:
            for m in cve.hasMitigation:
                mitigations.append(str(m.mitigationName) if hasattr(m, 'mitigationName') else str(m))

        detections = []
        if cve.hasDetectionMethod:
            for d in cve.hasDetectionMethod:
                detections.append(str(d.detectionName) if hasattr(d, 'detectionName') else str(d))

        controls = []
        if cve.hasSecurityControl:
            for c in cve.hasSecurityControl:
                controls.append(str(c.controlName) if hasattr(c, 'controlName') else str(c))

        if mitigations or detections or controls:
            profiles.append({
                "cve": cve_id,
                "mitigations": mitigations,
                "detections": detections,
                "controls": controls
            })

    passed = len(profiles) > 0
    return passed, profiles


def validate_cq10_similar_vulnerabilities(onto):
    """
    CQ10: Can we find similar vulnerability pairs (same CWE, same technique)?
    Query: Group CVEs by shared CWE and technique
    """
    similarity_groups = {}
    for cve in onto.CVE.instances():
        cwe_ids = []
        if cve.hasCWE:
            for cwe in cve.hasCWE:
                cwe_ids.append(str(cwe.cweId) if hasattr(cwe, 'cweId') else str(cwe))

        tech_ids = []
        if cve.hasAttackTechnique:
            for tech in cve.hasAttackTechnique:
                tech_ids.append(str(tech.attckId) if hasattr(tech, 'attckId') else str(tech))

        key = (tuple(sorted(cwe_ids)), tuple(sorted(tech_ids)))
        if key not in similarity_groups:
            similarity_groups[key] = []
        similarity_groups[key].append(str(cve.cveId) if hasattr(cve, 'cveId') else str(cve))

    # Filter groups with >1 CVE (actual pairs)
    pairs = {k: v for k, v in similarity_groups.items() if len(v) > 1}
    passed = len(pairs) > 0

    return passed, pairs


def validate_cq11_attack_path_tracing(onto):
    """
    CQ11: Can we trace attack paths (Actor → Campaign → Technique → CVE)?
    Query: Follow attributedTo and hasIndicator links
    """
    paths = []
    for campaign in onto.Campaign.instances():
        campaign_name = str(campaign).split("#")[-1] if "#" in str(campaign) else str(campaign)

        # Campaign → Actor
        actors = []
        if hasattr(campaign, 'attributedTo') and campaign.attributedTo:
            for actor in campaign.attributedTo:
                actors.append(str(actor).split("#")[-1] if "#" in str(actor) else str(actor))

        # Campaign → Indicator
        indicators = []
        if hasattr(campaign, 'hasIndicator') and campaign.hasIndicator:
            for ind in campaign.hasIndicator:
                indicators.append(str(ind).split("#")[-1] if "#" in str(ind) else str(ind))

        if actors or indicators:
            paths.append({
                "campaign": campaign_name,
                "actors": actors,
                "indicators": indicators
            })

    passed = len(paths) > 0
    return passed, paths


def validate_cq12_mitigation_gap(onto):
    """
    CQ12: Can we identify mitigation gaps (CVEs without mitigations)?
    Query: Find CVEs missing mitigation links
    """
    covered = []
    gaps = []

    for cve in onto.CVE.instances():
        cve_id = str(cve.cveId) if hasattr(cve, 'cveId') else str(cve)
        if cve.hasMitigation and len(cve.hasMitigation) > 0:
            covered.append(cve_id)
        else:
            gaps.append(cve_id)

    total = len(covered) + len(gaps)
    coverage = (len(covered) / total * 100) if total > 0 else 0
    passed = len(covered) > 0

    return passed, {
        "covered": len(covered),
        "gaps": len(gaps),
        "coverage": round(coverage, 2),
        "gap_examples": gaps[:5]  # Show first 5 gaps
    }


# ═══════════════════════════════════════════════════════════
# VALIDATION ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

def run_all_validations(onto):
    """Run all competency question validations and return results."""
    validations = [
        ("CQ1", "Critical RCE vulnerabilities", validate_cq1_critical_rce),
        ("CQ2", "CVSS score distribution", validate_cq2_cvss_distribution),
        ("CQ3", "XSS product ranking", validate_cq3_xss_ranking),
        ("CQ4", "CWE classification", validate_cq4_cwe_classification),
        ("CQ5", "ATT&CK technique mapping", validate_cq5_attack_technique_mapping),
        ("CQ6", "D3FEND countermeasure mapping", validate_cq6_d3fend_mapping),
        ("CQ7", "Multi-hop reasoning", validate_cq7_multihop_reasoning),
        ("CQ8", "Initial Access coverage", validate_cq8_initial_access_coverage),
        ("CQ9", "Complete defensive profile", validate_cq9_defensive_profile),
        ("CQ10", "Similar vulnerability pairs", validate_cq10_similar_vulnerabilities),
        ("CQ11", "Attack path tracing", validate_cq11_attack_path_tracing),
        ("CQ12", "Mitigation gap analysis", validate_cq12_mitigation_gap),
    ]

    results = []
    total_passed = 0
    total_failed = 0

    print("\n[*] Competency Question Validation")
    print("=" * 60)

    for cq_id, desc, validator in validations:
        try:
            passed, data = validator(onto)
            status = "PASS" if passed else "FAIL"
            if passed:
                total_passed += 1
            else:
                total_failed += 1

            # Print summary
            print(f"  {cq_id}: {desc:<35s} [{status}]")

            # Print details for passed CQs
            if passed and data:
                if isinstance(data, list) and len(data) > 0:
                    print(f"       → Found {len(data)} results")
                elif isinstance(data, dict):
                    if "coverage" in data:
                        print(f"       → Coverage: {data['coverage']}%")
                    elif "distribution" in data:
                        dist = data['distribution']
                        print(f"       → Distribution: {dist}")
                    elif "mapped" in data:
                        print(f"       → Mapped: {data['mapped']}/{data['mapped'] + data['unmapped']}")

            results.append({
                "id": cq_id,
                "description": desc,
                "status": status,
                "passed": passed,
                "data": data
            })
        except Exception as e:
            print(f"  {cq_id}: {desc:<35s} [ERROR: {str(e)[:30]}]")
            total_failed += 1
            results.append({
                "id": cq_id,
                "description": desc,
                "status": "ERROR",
                "passed": False,
                "error": str(e)
            })

    print(f"\n[+] Results: {total_passed} passed, {total_failed} failed out of {len(validations)}")

    return results
