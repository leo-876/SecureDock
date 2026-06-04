#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))
POLICY_PATH = Path(os.getenv("POLICY_PATH", "/policy/policy.yaml"))
PIPELINE_EVENT = os.getenv("PIPELINE_EVENT", "push")


def load_json(path):
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def load_policy():
    if POLICY_PATH.exists():
        with open(POLICY_PATH) as f:
            return yaml.safe_load(f)
    return {}


def count_by_severity(vulns):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        sev = v.get("severity", "low").lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def main():
    policy = load_policy()
    findings = load_json(REPORTS_DIR / "snyk_findings.json")
    sbom_delta = load_json(REPORTS_DIR / "sbom_delta.json")
    evaluation = load_json(REPORTS_DIR / "evaluation.json")

    vulns = findings.get("vulnerabilities", [])
    severity_counts = count_by_severity(vulns)
    event_policy = policy.get("gate", {}).get(f"block_on_{PIPELINE_EVENT}", {})

    violations = []

    max_critical = event_policy.get("max_critical", 0)
    if severity_counts["critical"] > max_critical:
        violations.append({
            "rule": "max_critical",
            "message": f"Found {severity_counts['critical']} critical CVEs (limit: {max_critical})",
            "severity": "critical"
        })

    max_high = event_policy.get("max_high", 0)
    if PIPELINE_EVENT == "merge" and severity_counts["high"] > max_high:
        violations.append({
            "rule": "max_high",
            "message": f"Found {severity_counts['high']} high CVEs (limit: {max_high})",
            "severity": "high"
        })

    if (event_policy.get("require_sbom_delta_clean") or
            policy.get("sbom", {}).get("block_on_new_cves")):
        if sbom_delta.get("is_regression"):
            new_cves = sbom_delta.get("new_cves", [])
            violations.append({
                "rule": "sbom_regression",
                "message": f"SBOM delta detected {len(new_cves)} new CVE(s): {new_cves}",
                "severity": "critical"
            })

    if PIPELINE_EVENT == "pr" and event_policy.get("require_ai_triage"):
        if not evaluation.get("tracks", {}).get("ai_agent"):
            violations.append({
                "rule": "require_ai_triage",
                "message": "AI triage results missing",
                "severity": "high"
            })

    gate_passed = len(violations) == 0
    decision = "PASS" if gate_passed else "BLOCK"

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pipeline_event": PIPELINE_EVENT,
        "decision": decision,
        "gate_passed": gate_passed,
        "severity_counts": severity_counts,
        "violations": violations,
        "sbom_delta_summary": sbom_delta.get("summary", {}),
        "best_remediation_track": evaluation.get("best_track", "unknown"),
        "policy_applied": event_policy
    }

    output_path = REPORTS_DIR / "gate_result.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n{'='*50}")
    print(f"  SECUREDOCK GATE: {decision}")
    print(f"{'='*50}")
    print(f"  Event: {PIPELINE_EVENT}")
    print(f"  Critical: {severity_counts['critical']} | High: {severity_counts['high']}")
    if violations:
        print(f"\n  Violations:")
        for v in violations:
            print(f"    [{v['severity'].upper()}] {v['message']}")
    else:
        print("  No policy violations.")
    print(f"{'='*50}\n")

    sys.exit(0 if gate_passed else 1)


if __name__ == "__main__":
    main()
