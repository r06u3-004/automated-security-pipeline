#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

REPORT_DIR = "reports"
REPORT_FILE = os.path.join(REPORT_DIR, "pytest.json")


def run_pytest():
    os.makedirs(REPORT_DIR, exist_ok=True)

    start = time.time()

    process = subprocess.run(
        ["pytest", "-v"],
        capture_output=True,
        text=True
    )

    duration = round(time.time() - start, 2)

    output = process.stdout + process.stderr

    # Recherche du résumé pytest :
    # 5 passed in 0.11s
    summary_match = re.search(
        r"(?:(\d+) failed[, ]*)?"
        r"(?:(\d+) passed[, ]*)?"
        r"(?:(\d+) skipped[, ]*)?"
        r"(?:(\d+) error[s]?[, ]*)?"
        r"in ([0-9.]+)s",
        output
    )

    failed = 0
    passed = 0
    skipped = 0
    errors = 0

    if summary_match:
        failed = int(summary_match.group(1) or 0)
        passed = int(summary_match.group(2) or 0)
        skipped = int(summary_match.group(3) or 0)
        errors = int(summary_match.group(4) or 0)

    collected_match = re.search(
        r"collected (\d+) items",
        output
    )

    collected = (
        int(collected_match.group(1))
        if collected_match
        else passed + failed + skipped + errors
    )

    status = "PASSED" if process.returncode == 0 else "FAILED"

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": "pytest",
        "stage": "Automated Tests",
        "status": status,
        "exit_code": process.returncode,
        "tests": {
            "collected": collected,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "errors": errors
        },
        "duration_seconds": duration,
        "command": "pytest -v",
        "raw_output": output
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)

    print(json.dumps(report, indent=2, ensure_ascii=False))

    return process.returncode


if __name__ == "__main__":
    sys.exit(run_pytest())
