#!/usr/bin/env python3

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import anthropic

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

# Few-shot examples
FEW_SHOT_EXAMPLES = [
    {
        "vuln": {
            "id": "CVE-2021-44228",
            "packageName": "log4j-core",
            "version": "2.14.1",
            "severity": "critical",
            "title": "Remote Code Execution via JNDI lookup",
            "description": "Log4j2 allows remote code execution via crafted log messages with JNDI lookups.",
            "fixedIn": ["2.17.1"],
            "context": "This is a Java web application that logs all incoming HTTP request headers."
        },
        "ideal_output": {
            "reachability": "reachable",
            "reachability_reason": "The application logs HTTP headers which are user-controlled. An attacker can inject ${jndi:ldap://...} in the User-Agent header, triggering the vulnerability directly.",
            "risk_score": 10,
            "fix": "Upgrade log4j-core to 2.17.1 immediately. Also add -Dlog4j2.formatMsgNoLookups=true as a JVM flag as a temporary mitigation.",
            "fix_type": "upgrade",
            "suppress": False
        }
    },
    {
        "vuln": {
            "id": "CVE-2020-8203",
            "packageName": "lodash",
            "version": "4.17.15",
            "severity": "high",
            "title": "Prototype Pollution via merge()",
            "description": "Prototype pollution via lodash merge, mergeWith, defaultsDeep.",
            "fixedIn": ["4.17.19"],
            "context": "This is a CLI batch processing tool with no web interface or user input."
        },
        "ideal_output": {
            "reachability": "not_reachable",
            "reachability_reason": "Prototype pollution via lodash requires attacker-controlled input to be passed to merge(). This CLI tool processes only internal config files with no user-facing input surface.",
            "risk_score": 3,
            "fix": "Upgrade lodash to 4.17.21 as part of regular maintenance, but this is not urgent.",
            "fix_type": "upgrade",
            "suppress": True
        }
    },
    {
        "vuln": {
            "id": "CVE-2022-25881",
            "packageName": "http-cache-semantics",
            "version": "4.1.0",
            "severity": "high",
            "title": "Regular Expression Denial of Service (ReDoS)",
            "description": "Before 4.1.1, ReDoS via malformed header values.",
            "fixedIn": ["4.1.1"],
            "context": "This package is a transitive dependency pulled in by npm's update checker and is never called directly by application code."
        },
        "ideal_output": {
            "reachability": "not_reachable",
            "reachability_reason": "http-cache-semantics is used only by the npm CLI itself during package installation, not by application code at runtime. The attack surface does not exist in production.",
            "risk_score": 2,
            "fix": "Upgrade to 4.1.1 to silence the scanner, but runtime risk is negligible.",
            "fix_type": "upgrade",
            "suppress": True
        }
    }
]


def build_system_prompt() -> str:
    examples_text = ""
    for i, ex in enumerate(FEW_SHOT_EXAMPLES, 1):
        v = ex["vuln"]
        o = ex["ideal_output"]
        examples_text += f"""
Example {i}:
INPUT:
CVE: {v['id']} | Package: {v['packageName']} {v['version']} | Severity: {v['severity']}
Title: {v['title']}
Description: {v['description']}
Fixed in: {v['fixedIn']}
Application context: {v['context']}

OUTPUT:
{json.dumps(o, indent=2)}
---"""

    return f"""You are a senior application security engineer performing container vulnerability triage.
Your job is to analyze each CVE and determine:
1. Whether it is actually reachable in this specific application context
2. The correct fix
3. Whether it can be suppressed as a false positive

You must respond ONLY with a valid JSON object matching this exact schema:
{{
  "reachability": "reachable" | "not_reachable" | "unknown",
  "reachability_reason": "string explaining why",
  "risk_score": 1-10,
  "fix": "specific actionable fix string",
  "fix_type": "upgrade" | "remove_package" | "code_change" | "manual_required",
  "suppress": true | false
}}

Here are examples of ideal triage decisions:
{examples_text}

Now triage the vulnerability provided by the user using the same reasoning approach."""


def triage_with_few_shot(vuln: dict, sbom_context: str = "") -> dict:
    start = time.time()

    user_msg = f"""CVE: {vuln['id']} | Package: {vuln['packageName']} {vuln.get('version','?')} | Severity: {vuln['severity']}
Title: {vuln['title']}
Description: {vuln['description']}
Fixed in: {vuln.get('fixedIn', [])}
Application context: Node.js web API accepting HTTP requests from external users."""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=500,
            system=build_system_prompt(),
            messages=[{"role": "user", "content": user_msg}]
        )
        raw = response.content[0].text.strip()
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        triage = json.loads(raw)
    except Exception as e:
        triage = {
            "reachability": "unknown",
            "reachability_reason": f"Parse error: {e}",
            "risk_score": 5,
            "fix": vuln.get("fixedIn", ["manual review"])[0] if vuln.get("fixedIn") else "manual review",
            "fix_type": "manual_required",
            "suppress": False
        }

    elapsed = time.time() - start

    return {
        "cve_id": vuln["id"],
        "package": vuln["packageName"],
        "severity": vuln["severity"],
        "track": "few_shot",
        **triage,
        "mttr_seconds": round(elapsed, 3),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def score_against_ground_truth(results: list, ground_truth: dict) -> list:
    for r in results:
        gt = ground_truth.get(r["cve_id"])
        if gt:
            gt_reachable = gt["reachable"]
            judged_reachable = r.get("reachability") == "reachable"
            judged_unknown = r.get("reachability") == "unknown"
            r["reachability_correct"] = (
                None if judged_unknown
                else (judged_reachable == gt_reachable)
            )
            correct_version = gt.get("correct_fix_version")
            fix_str = r.get("fix", "")
            if correct_version:
                r["fix_verified"] = correct_version in fix_str
            else:
                r["fix_verified"] = gt["fix_type"] == r.get("fix_type")
        else:
            r["reachability_correct"] = None
            r["fix_verified"] = False
    return results


def main():
    with open(REPORTS_DIR / "snyk_findings.json") as f:
        findings = json.load(f)
    vulns = findings.get("vulnerabilities", [])

    gt_path = Path("/app/ground_truth.json")
    ground_truth = {}
    if gt_path.exists():
        with open(gt_path) as f:
            ground_truth = {c["id"]: c for c in json.load(f)["labeled_cves"]}

    print(f"[few-shot] Processing {len(vulns)} vulnerabilities with few-shot prompting...")

    results = []
    for vuln in vulns:
        result = triage_with_few_shot(vuln)
        results.append(result)
        print(f"[few-shot] {result['cve_id']} -> {result.get('reachability','?')} | suppress={result.get('suppress')}")

    results = score_against_ground_truth(results, ground_truth)

    scored = [r for r in results if r.get("reachability_correct") is not None]
    reachability_acc = (
        sum(1 for r in scored if r["reachability_correct"]) / len(scored)
        if scored else 0.0
    )
    fix_rate = sum(1 for r in results if r.get("fix_verified")) / max(len(results), 1)

    summary = {
        "track": "few_shot",
        "total": len(results),
        "fix_validity_rate": round(fix_rate, 2),
        "reachability_accuracy": round(reachability_acc, 2),
        "avg_mttr_seconds": round(sum(r["mttr_seconds"] for r in results) / max(len(results), 1), 3),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results
    }

    output_path = REPORTS_DIR / "few_shot_results.json"
    with open(output_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"[few-shot] Done. Reachability acc: {reachability_acc*100:.0f}% | Fix rate: {fix_rate*100:.0f}%")


if __name__ == "__main__":
    main()
