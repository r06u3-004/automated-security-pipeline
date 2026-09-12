#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone

REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "semgrep_report.json")


def run_semgrep():

    os.makedirs(REPORT_DIR, exist_ok=True)

    start = time.time()

    process = subprocess.run(
        [
            "semgrep",
            "--config=auto",
            "--json",
            "--exclude=__pycache__",
            "--exclude=*.pyc",
            "app/"
        ],
        capture_output=True,
        text=True
    )

    duration = round(time.time() - start, 2)

    try:
        semgrep_data = json.loads(process.stdout)
    except json.JSONDecodeError:
        print("Erreur : sortie JSON Semgrep invalide.")
        print(process.stderr)
        sys.exit(1)

    results = semgrep_data.get("results", [])

    severity_counter = Counter()

    findings = []

    for result in results:

        extra = result.get("extra", {})

        severity = extra.get("severity", "UNKNOWN").upper()

        severity_counter[severity] += 1

        findings.append({
            "rule": result.get("check_id"),
            "path": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "end_line": result.get("end", {}).get("line"),
            "severity": severity,
            "message": extra.get("message", "")
        })

    errors = semgrep_data.get("errors", [])

    scanned_files = semgrep_data.get("paths", {}).get("scanned", [])

    status = "PASSED"

    if process.returncode != 0:
        status = "FAILED"
    elif results:
        status = "WARNING"

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "tool": "semgrep",

        "stage": "SAST — Semgrep",

        "status": status,

        "exit_code": process.returncode,

        "summary": {
            "findings": len(results),
            "error": severity_counter.get("ERROR", 0),
            "warning": severity_counter.get("WARNING", 0),
            "info": severity_counter.get("INFO", 0),
            "unknown": severity_counter.get("UNKNOWN", 0),
            "scanner_errors": len(errors)
        },

        "scan": {
            "files_scanned": scanned_files,
            "files_count": len(scanned_files),
            "version": semgrep_data.get("version"),
            "engine": semgrep_data.get("engine_requested")
        },

        "performance": {
            "duration_seconds": duration,
            "semgrep_total_seconds": (
                semgrep_data
                .get("time", {})
                .get("profiling_times", {})
                .get("total_time")
            ),
            "max_memory_bytes": (
                semgrep_data
                .get("time", {})
                .get("max_memory_bytes")
            )
        },

        "command": (
            "semgrep --config=auto --json "
            "--exclude=__pycache__ --exclude=*.pyc app/"
        ),

        "findings": findings,

        "scanner_errors": errors,

        "raw_output": semgrep_data
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(json.dumps(
        report,
        indent=2,
        ensure_ascii=False
    ))

    return 0 if status != "FAILED" else 1


if __name__ == "__main__":
    sys.exit(run_semgrep())
