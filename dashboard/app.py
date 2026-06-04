#!/usr/bin/env python3

import json
import os
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify

app = Flask(__name__)
REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))


def load_json(filename: str) -> dict:
    path = REPORTS_DIR / filename
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def get_dashboard_data():
    evaluation = load_json("evaluation.json")
    gate = load_json("gate_result.json")
    sbom_delta = load_json("sbom_delta.json")
    findings = load_json("snyk_findings.json")
    return {
        "evaluation": evaluation,
        "gate": gate,
        "sbom_delta": sbom_delta,
        "total_cves": len(findings.get("vulnerabilities", [])),
        "scan_time": findings.get("scannedAt", "N/A"),
        "image": findings.get("imageName", "N/A"),
    }


@app.route("/")
def index():
    data = get_dashboard_data()
    return render_template("index.html", data=data)


@app.route("/api/data")
def api_data():
    return jsonify(get_dashboard_data())


@app.route("/api/evaluation")
def api_evaluation():
    return jsonify(load_json("evaluation.json"))


@app.route("/api/gate")
def api_gate():
    return jsonify(load_json("gate_result.json"))


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
