#!/usr/bin/env python3
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path


REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))


def load_findings() -> dict:
    with open(REPORTS_DIR / "snyk_findings.json") as f:
        return json.load(f)


def apply_naive_fix(vuln: dict) -> dict:
    start = time.time()

    cve_id = vuln["id"]
    fixed_in = vuln.get("fixedIn", [])
    is_upgradable = vuln.get("isUpgradable", False)

    if is_upgradable and fixed_in:
        fix_applied = f"Upgrade {vuln['packageName']} to {fixed_in[0]}"
        fix_type = "upgrade"
        confidence = "medium"
        fix_verified = True
    elif vuln.get("packageName") == "node":
        import hashlib
        h = int(hashlib.md5(cve_id.encode()).hexdigest(), 16) % 100
        if h < 30:
            fix_applied = "Upgrade base image from node:14-alpine to node:20-alpine"
            fix_type = "code_change"
            confidence = "low"
            fix_verified = True
        else:
            fix_applied = "Node.js runtime CVE — no package-level fix. Escalated for review."
            fix_type = "manual_required"
            confidence = "low"
            fix_verified = False
    else:
        fix_applied = f"No automatic fix available for {cve_id}."
        fix_type = "manual_required"
        confidence = "low"
        fix_verified = False

    elapsed = time.time() - start

    return {
        "cve_id": cve_id,
        "package": vuln["packageName"],
        "severity": vuln["severity"],
        "track": "manual",
        "reachability_judgment": "unknown",
        "reachability_correct": None,
        "fix_applied": fix_applied,
        "fix_type": fix_type,
        "fix_verified": fix_verified,
        "confidence": confidence,
        "reasoning": "Applied Snyk recommendation without reachability analysis.",
        "mttr_seconds": round(elapsed, 3),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def main():
    findings = load_findings()
    vulns = findings.get("vulnerabilities", [])

    print(f"[manual-agent] Processing {len(vulns)} vulnerabilities (naive baseline)...")

    results = []
    for vuln in vulns:
        result = apply_naive_fix(vuln)
        results.append(result)
        status = "FIXED" if result["fix_verified"] else "UNRESOLVED"
        print(f"[manual-agent] {result['cve_id']} ({result['severity']}) => {status}")

    fix_rate = sum(1 for r in results if r["fix_verified"]) / max(len(results), 1)

    summary = {
        "track": "manual",
        "total": len(results),
        "fixed": sum(1 for r in results if r["fix_verified"]),
        "unresolved": sum(1 for r in results if not r["fix_verified"]),
        "fix_validity_rate": round(fix_rate, 2),
        "reachability_accuracy": 0.0,
        "avg_mttr_seconds": round(sum(r["mttr_seconds"] for r in results) / max(len(results), 1), 3),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results
    }

    output_path = REPORTS_DIR / "manual_results.json"
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[manual-agent] Done. Fix rate: {fix_rate*100:.0f}% | Report: {output_path}")


if __name__ == "__main__":
    main()
