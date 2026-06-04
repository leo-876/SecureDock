#!/usr/bin/env python3
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path


REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))
BASELINE_DIR = Path(os.getenv("BASELINE_DIR", "/baseline"))


def load_json(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def extract_purls(sbom: dict) -> set:
    return {
        c.get("purl", f"{c['name']}@{c.get('version','?')}")
        for c in sbom.get("components", [])
    }


def extract_cve_ids(findings: dict) -> set:
    return {v["id"] for v in findings.get("vulnerabilities", [])}


def main():
    current_sbom = load_json(REPORTS_DIR / "sbom.json")
    baseline_sbom = load_json(BASELINE_DIR / "sbom_baseline.json")
    current_findings = load_json(REPORTS_DIR / "snyk_findings.json")
    baseline_findings = load_json(BASELINE_DIR / "findings_baseline.json")

    new_cves = extract_cve_ids(current_findings) - extract_cve_ids(baseline_findings)
    resolved_cves = extract_cve_ids(baseline_findings) - extract_cve_ids(current_findings)
    new_packages = extract_purls(current_sbom) - extract_purls(baseline_sbom)
    removed_packages = extract_purls(baseline_sbom) - extract_purls(current_sbom)

    is_regression = len(new_cves) > 0

    delta = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "is_regression": is_regression,
        "summary": {
            "new_cves_introduced": len(new_cves),
            "cves_resolved": len(resolved_cves),
            "new_packages_added": len(new_packages),
            "packages_removed": len(removed_packages)
        },
        "new_cves": list(new_cves),
        "resolved_cves": list(resolved_cves),
        "new_packages": list(new_packages),
        "removed_packages": list(removed_packages),
        "gate_recommendation": "BLOCK" if is_regression else "PASS"
    }

    output_path = REPORTS_DIR / "sbom_delta.json"
    with open(output_path, "w") as f:
        json.dump(delta, f, indent=2)

    if not is_regression and current_sbom:
        BASELINE_DIR.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPORTS_DIR / "sbom.json", BASELINE_DIR / "sbom_baseline.json")
        shutil.copy(REPORTS_DIR / "snyk_findings.json", BASELINE_DIR / "findings_baseline.json")
        print("[sbom-differ] Baseline updated.")

    status = "REGRESSION DETECTED" if is_regression else "CLEAN"
    print(f"[sbom-differ] Delta: {status} | New CVEs: {list(new_cves)} | Resolved: {list(resolved_cves)}")


if __name__ == "__main__":
    main()
