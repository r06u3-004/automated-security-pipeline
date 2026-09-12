#!/usr/bin/env python3

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

REPORT_DIR = "reports"

FS_REPORT = os.path.join(REPORT_DIR, "trivy-fs.json")
IMAGE_REPORT = os.path.join(REPORT_DIR, "trivy-image.json")
OUTPUT_REPORT = os.path.join(REPORT_DIR, "trivy.json")


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def extract_vulnerabilities(data, source):
    vulnerabilities = []

    for result in data.get("Results", []):

        target = result.get("Target", "")
        result_type = result.get("Type", "")

        for vuln in result.get("Vulnerabilities", []):

            severity = vuln.get("Severity", "UNKNOWN").upper()

            vulnerabilities.append({
                "source": source,
                "target": target,
                "type": result_type,
                "vulnerability_id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed_version": vuln.get("InstalledVersion"),
                "fixed_version": vuln.get("FixedVersion"),
                "severity": severity,
                "title": vuln.get("Title"),
                "description": vuln.get("Description"),
                "primary_url": vuln.get("PrimaryURL"),
                "cvss": vuln.get("CVSS", {})
            })

    return vulnerabilities


def main():

    os.makedirs(REPORT_DIR, exist_ok=True)

    if not os.path.exists(FS_REPORT):
        print(f"Erreur : {FS_REPORT} introuvable.")
        sys.exit(1)

    if not os.path.exists(IMAGE_REPORT):
        print(f"Erreur : {IMAGE_REPORT} introuvable.")
        sys.exit(1)

    fs_data = load_json(FS_REPORT)
    image_data = load_json(IMAGE_REPORT)

    vulnerabilities = []

    vulnerabilities.extend(
        extract_vulnerabilities(
            fs_data,
            "filesystem"
        )
    )

    vulnerabilities.extend(
        extract_vulnerabilities(
            image_data,
            "container_image"
        )
    )

    severity_counter = Counter(
        vuln["severity"]
        for vuln in vulnerabilities
    )

    critical = severity_counter.get("CRITICAL", 0)
    high = severity_counter.get("HIGH", 0)
    medium = severity_counter.get("MEDIUM", 0)
    low = severity_counter.get("LOW", 0)
    unknown = severity_counter.get("UNKNOWN", 0)

    total = len(vulnerabilities)

    scanner_errors = (
        len(fs_data.get("Errors", []))
        + len(image_data.get("Errors", []))
    )

    if scanner_errors > 0:
        status = "FAILED"
    elif critical > 0 or high > 0:
        status = "WARNING"
    elif medium > 0 or low > 0:
        status = "WARNING"
    else:
        status = "PASSED"

    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),

        "tool": "trivy",

        "stage": "SCA + Container Security — Trivy",

        "status": status,

        "summary": {
            "total_vulnerabilities": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "unknown": unknown,
            "scanner_errors": scanner_errors
        },

        "scans": {
            "filesystem": {
                "artifact": fs_data.get("ArtifactName"),
                "type": fs_data.get("ArtifactType"),
                "trivy_version": (
                    fs_data.get("Trivy", {}).get("Version")
                )
            },

            "container_image": {
                "artifact": image_data.get("ArtifactName"),
                "type": image_data.get("ArtifactType"),
                "image_id": image_data.get("ArtifactID"),
                "trivy_version": (
                    image_data.get("Trivy", {}).get("Version")
                ),
                "os": image_data.get("Metadata", {}).get("OS", {})
            }
        },

        "vulnerabilities": vulnerabilities,

        "commands": {
            "filesystem": (
                "trivy fs --scanners vuln "
                "--format json "
                "--output reports/trivy-fs.json app/"
            ),

            "container_image": (
                "trivy image --scanners vuln "
                "--format json "
                "--output reports/trivy-image.json "
                "devsecops-lab-app:latest"
            )
        },

        "scanner_errors": (
            fs_data.get("Errors", [])
            + image_data.get("Errors", [])
        )
    }

    with open(
        OUTPUT_REPORT,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False
        )

    print(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False
        )
    )


if __name__ == "__main__":
    main()
