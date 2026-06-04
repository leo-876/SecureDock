#!/usr/bin/env python3
import json
import os
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))
GT_PATH = Path(os.getenv("GROUND_TRUTH_PATH", "/app/ground_truth.json"))


def load_json(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def compute_weighted_score(track_summary: dict) -> float:
    track = track_summary.get("track", "")
    fvr = track_summary.get("fix_validity_rate", 0.0)
    fpr = 1.0 - track_summary.get("false_positive_rate", 0.0)
    avg_mttr = track_summary.get("avg_mttr_seconds", 30)
    mttr_score = max(0, 1.0 - (avg_mttr / 60.0))

    if track == "manual":
        return round(fvr * 0.55 + fpr * 0.35 + mttr_score * 0.10, 3)
    else:
        ra = track_summary.get("reachability_accuracy", 0.0)
        return round(ra * 0.35 + fvr * 0.40 + fpr * 0.15 + mttr_score * 0.10, 3)


def evaluate_track(track_data: dict, ground_truth: dict) -> dict:
    results = track_data.get("results", [])
    if not results:
        return track_data

    track = track_data.get("track", "")
    false_positives = 0
    reachability_correct = 0

    for r in results:
        gt = ground_truth.get(r["cve_id"])
        if not gt or track == "manual":
            continue

        gt_reachable = gt["reachable"]
        judged = r.get("reachability_judgment", r.get("reachability", "unknown"))

        if judged != "unknown":
            judged_reachable = judged == "reachable"
            if judged_reachable == gt_reachable:
                reachability_correct += 1
            elif not gt_reachable and judged_reachable:
                false_positives += 1

    total_scoreable = sum(1 for r in results if ground_truth.get(r["cve_id"])) if track != "manual" else 0
    reachability_acc = reachability_correct / max(total_scoreable, 1) if track != "manual" else 0.0
    fpr = false_positives / max(len(results), 1)

    track_data["reachability_accuracy"] = round(reachability_acc, 2)
    track_data["false_positive_rate"] = round(fpr, 2)
    track_data["weighted_score"] = compute_weighted_score(
        {**track_data, "false_positive_rate": fpr, "reachability_accuracy": reachability_acc}
    )
    return track_data


def build_cve_comparison(manual, zero_shot, few_shot, ai_agent, ground_truth) -> list:
    all_cve_ids = set()
    for track in [manual, zero_shot, few_shot, ai_agent]:
        for r in track.get("results", []):
            all_cve_ids.add(r["cve_id"])

    def find_result(track_data, cve_id):
        return next((r for r in track_data.get("results", []) if r["cve_id"] == cve_id), None)

    comparison = []
    for cve_id in sorted(all_cve_ids):
        gt = ground_truth.get(cve_id, {})
        m = find_result(manual, cve_id)
        z = find_result(zero_shot, cve_id)
        f = find_result(few_shot, cve_id)
        a = find_result(ai_agent, cve_id)

        comparison.append({
            "cve_id": cve_id,
            "severity": gt.get("severity", m["severity"] if m else "unknown"),
            "ground_truth_reachable": gt.get("reachable"),
            "ground_truth_fix": gt.get("correct_fix"),
            "tracks": {
                "manual": {"reachability": "unknown", "fix_verified": m.get("fix_verified") if m else False, "reachability_correct": None} if m else None,
                "zero_shot": {"reachability": z.get("reachability_judgment", z.get("reachability")) if z else None, "fix_verified": z.get("fix_verified") if z else False, "reachability_correct": z.get("reachability_correct") if z else None} if z else None,
                "few_shot": {"reachability": f.get("reachability") if f else None, "fix_verified": f.get("fix_verified") if f else False, "reachability_correct": f.get("reachability_correct") if f else None} if f else None,
                "ai_agent": {"reachability": a.get("reachability") if a else None, "fix_verified": a.get("fix_verified") if a else False, "reachability_correct": a.get("reachability_correct") if a else None, "fix_description": a.get("fix_description") if a else None, "pr_url": a.get("pr_url") if a else None} if a else None
            }
        })
    return comparison


def main():
    manual = load_json(REPORTS_DIR / "manual_results.json")
    zero_shot = load_json(REPORTS_DIR / "zero_shot_results.json")
    few_shot = load_json(REPORTS_DIR / "few_shot_results.json")
    ai_agent = load_json(REPORTS_DIR / "ai_agent_results.json")
    sbom_delta = load_json(REPORTS_DIR / "sbom_delta.json")

    ground_truth = {}
    if GT_PATH.exists():
        with open(GT_PATH) as f:
            ground_truth = {c["id"]: c for c in json.load(f)["labeled_cves"]}

    manual = evaluate_track(manual, ground_truth)
    zero_shot = evaluate_track(zero_shot, ground_truth)
    few_shot = evaluate_track(few_shot, ground_truth)
    ai_agent = evaluate_track(ai_agent, ground_truth)

    best_track = max(
        [manual, zero_shot, few_shot, ai_agent],
        key=lambda t: t.get("weighted_score", 0)
    ).get("track", "ai_agent")

    evaluation = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "best_track": best_track,
        "sbom_delta": sbom_delta,
        "tracks": {
            "manual": {
                "label": "Manual Remediation",
                "description": "Applies Snyk suggested fixes verbatim without reasoning",
                "fix_validity_rate": manual.get("fix_validity_rate", 0),
                "reachability_accuracy": manual.get("reachability_accuracy", 0),
                "false_positive_rate": manual.get("false_positive_rate", 0),
                "avg_mttr_seconds": manual.get("avg_mttr_seconds", 0),
                "weighted_score": manual.get("weighted_score", 0),
            },
            "zero_shot": {
                "label": "Zero-Shot LLM",
                "description": "Claude with a minimal prompt and no examples",
                "fix_validity_rate": zero_shot.get("fix_validity_rate", 0),
                "reachability_accuracy": zero_shot.get("reachability_accuracy", 0),
                "false_positive_rate": zero_shot.get("false_positive_rate", 0),
                "avg_mttr_seconds": zero_shot.get("avg_mttr_seconds", 0),
                "weighted_score": zero_shot.get("weighted_score", 0),
            },
            "few_shot": {
                "label": "Few-Shot LLM",
                "description": "Claude with hand-crafted triage examples in the prompt",
                "fix_validity_rate": few_shot.get("fix_validity_rate", 0),
                "reachability_accuracy": few_shot.get("reachability_accuracy", 0),
                "false_positive_rate": few_shot.get("false_positive_rate", 0),
                "avg_mttr_seconds": few_shot.get("avg_mttr_seconds", 0),
                "weighted_score": few_shot.get("weighted_score", 0),
            },
            "ai_agent": {
                "label": "Engineered AI Agent",
                "description": "Claude with structured prompt, SBOM context, and policy enforcement",
                "fix_validity_rate": ai_agent.get("fix_validity_rate", 0),
                "reachability_accuracy": ai_agent.get("reachability_accuracy", 0),
                "false_positive_rate": ai_agent.get("false_positive_rate", 0),
                "avg_mttr_seconds": ai_agent.get("avg_mttr_seconds", 0),
                "weighted_score": ai_agent.get("weighted_score", 0),
                "prs_opened": ai_agent.get("prs_opened", 0),
            }
        },
        "cve_comparison": build_cve_comparison(manual, zero_shot, few_shot, ai_agent, ground_truth)
    }

    output_path = REPORTS_DIR / "evaluation.json"
    with open(output_path, "w") as f:
        json.dump(evaluation, f, indent=2)

    print(f"[evaluator] Evaluation complete. Best track: {best_track}")
    for name, t in evaluation["tracks"].items():
        print(f"  {name:12} | fix_rate={t['fix_validity_rate']*100:.0f}% | reach_acc={t['reachability_accuracy']*100:.0f}% | score={t['weighted_score']:.2f}")


if __name__ == "__main__":
    main()
