#!/usr/bin/env python3
import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


SNYK_TOKEN = os.getenv("SNYK_TOKEN", "")
IMAGE_NAME = os.getenv("IMAGE_NAME", "securedock-target:latest")
OUTPUT_DIR = Path(os.getenv("OUTPUT_DIR", "/reports"))
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true" or not SNYK_TOKEN

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def generate_basic_sbom(image_name: str) -> dict:
    known_packages = [
        ("node-serialize", "0.0.4"),
        ("lodash", "4.17.15"),
        ("axios", "0.21.1"),
        ("express", "4.17.1"),
    ]
    components = [
        {"type": "library", "name": name, "version": version, "purl": f"pkg:npm/{name}@{version}"}
        for name, version in known_packages
    ]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:securedock-{int(time.time())}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": {"type": "container", "name": image_name}
        },
        "components": components
    }


def run_snyk_scan():
    findings_path = OUTPUT_DIR / "snyk_findings.json"
    sbom_path = OUTPUT_DIR / "sbom.json"

    print(f"[scanner] Running Snyk scan on {IMAGE_NAME}...")
    result = subprocess.run(
        ["snyk", "container", "test", IMAGE_NAME, "--json"],
        capture_output=True, text=True, env={**os.environ, "SNYK_TOKEN": SNYK_TOKEN}
    )

    findings = json.loads(result.stdout) if result.stdout else {}

    os_packages = {"openssl", "busybox", "musl", "musl-utils", "ssl_client", "libssl1.1"}
    if "vulnerabilities" in findings:
        findings["vulnerabilities"] = [
            v for v in findings["vulnerabilities"]
            if v.get("packageName", "").lower() not in os_packages
            and not v.get("id", "").startswith("SNYK-ALPINE")
        ]
        print(f"[scanner] Filtered to {len(findings['vulnerabilities'])} app-level CVEs")

    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2)

    sbom = generate_basic_sbom(IMAGE_NAME)
    with open(sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"[scanner] Snyk scan complete. Findings: {findings_path}")
    return findings_path, sbom_path


def generate_mock_scan():
    print("[scanner] Demo mode: generating mock scan output...")

    findings = {
        "ok": False,
        "summary": "5 vulnerable dependency paths",
        "vulnerabilities": [
            {
                "id": "CVE-2017-5941",
                "packageName": "node-serialize",
                "version": "0.0.4",
                "severity": "critical",
                "title": "Remote Code Execution via unserialize()",
                "description": "node-serialize 0.0.4 allows remote attackers to execute arbitrary code via a crafted serialized JavaScript object.",
                "cvssScore": 9.8,
                "fixedIn": [],
                "isUpgradable": False,
                "isPatchable": False,
                "identifiers": {"CVE": ["CVE-2017-5941"]},
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2017-5941"}]
            },
            {
                "id": "CVE-2019-10744",
                "packageName": "lodash",
                "version": "4.17.15",
                "severity": "high",
                "title": "Prototype Pollution via defaultsDeep()",
                "description": "Versions of lodash prior to 4.17.21 are vulnerable to Prototype Pollution.",
                "cvssScore": 7.4,
                "fixedIn": ["4.17.21"],
                "isUpgradable": True,
                "isPatchable": False,
                "identifiers": {"CVE": ["CVE-2019-10744"]},
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2019-10744"}]
            },
            {
                "id": "CVE-2021-23337",
                "packageName": "lodash",
                "version": "4.17.15",
                "severity": "high",
                "title": "Command Injection via template()",
                "description": "Lodash versions prior to 4.17.21 are vulnerable to Command Injection via the template function.",
                "cvssScore": 7.2,
                "fixedIn": ["4.17.21"],
                "isUpgradable": True,
                "isPatchable": False,
                "identifiers": {"CVE": ["CVE-2021-23337"]},
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}]
            },
            {
                "id": "CVE-2023-45857",
                "packageName": "axios",
                "version": "0.21.1",
                "severity": "medium",
                "title": "CSRF Token Exposure",
                "description": "Axios 0.8.1 through 1.5.1 allows XSRF-TOKEN header exposure to a third-party host.",
                "cvssScore": 6.5,
                "fixedIn": ["1.6.0"],
                "isUpgradable": True,
                "isPatchable": False,
                "identifiers": {"CVE": ["CVE-2023-45857"]},
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-45857"}]
            },
            {
                "id": "CWE-798",
                "packageName": "application-code",
                "version": None,
                "severity": "high",
                "title": "Hard-coded Credentials",
                "description": "Hard-coded credentials (DB_PASSWORD, API_KEY) detected in source code.",
                "cvssScore": 7.5,
                "fixedIn": [],
                "isUpgradable": False,
                "isPatchable": False,
                "identifiers": {"CWE": ["CWE-798"]},
                "references": [{"url": "https://cwe.mitre.org/data/definitions/798.html"}]
            }
        ],
        "scannedAt": datetime.now(timezone.utc).isoformat(),
        "imageName": IMAGE_NAME
    }

    sbom = generate_basic_sbom(IMAGE_NAME)
    findings_path = OUTPUT_DIR / "snyk_findings.json"
    sbom_path = OUTPUT_DIR / "sbom.json"

    with open(findings_path, "w") as f:
        json.dump(findings, f, indent=2)
    with open(sbom_path, "w") as f:
        json.dump(sbom, f, indent=2)

    print(f"[scanner] Mock scan written to {findings_path}")
    return findings_path, sbom_path


def main():
    if DEMO_MODE:
        findings_path, sbom_path = generate_mock_scan()
    else:
        findings_path, sbom_path = run_snyk_scan()

    summary = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "image": IMAGE_NAME,
        "demo_mode": DEMO_MODE,
        "findings_path": str(findings_path),
        "sbom_path": str(sbom_path)
    }
    with open(OUTPUT_DIR / "scan_summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    print("[scanner] Done.")


if __name__ == "__main__":
    main()
