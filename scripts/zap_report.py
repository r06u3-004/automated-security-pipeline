#!/usr/bin/env python3

import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

REPORT_DIR = "reports"
INPUT_FILE = os.path.join(REPORT_DIR, "zap.json")
OUTPUT_FILE = os.path.join(REPORT_DIR, "zap_report.json")


RISK_MAP = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL"
}


def clean_html(text):
    if not text:
        return ""

    replacements = {
        "<p>": "",
        "</p>": " ",
        "<br>": "\n",
        "<br/>": "\n",
        "<br />": "\n",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return " ".join(text.split())


def load_report():

    if not os.path.exists(INPUT_FILE):
        print(f"Erreur : {INPUT_FILE} introuvable.")
        sys.exit(1)

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def main():

    data = load_report()

    alerts = []

    for site in data.get("site", []):

        site_name = site.get("@name")

        for alert in site.get("alerts", []):

            risk_code = str(
                alert.get("riskcode", "0")
            )

            risk = RISK_MAP.get(
                risk_code,
                "UNKNOWN"
            )

            instances = []

            for instance in alert.get(
                "instances",
                []
            ):

                instances.append({
                    "uri": instance.get("uri"),
                    "method": instance.get("method"),
                    "parameter": instance.get("param"),
                    "evidence": instance.get("evidence")
                })

            alerts.append({
                "site": site_name,
                "plugin_id": alert.get("pluginid"),
                "alert_ref": alert.get("alertRef"),
                "name": alert.get("alert"),
                "risk": risk,
                "risk_code": risk_code,
                "confidence": alert.get("confidence"),
                "count": int(
                    alert.get("count", 0)
                ),
                "description": clean_html(
                    alert.get("desc")
                ),
                "solution": clean_html(
                    alert.get("solution")
                ),
                "cwe_id": alert.get("cweid"),
                "wasc_id": alert.get("wascid"),
                "instances": instances
            })

    risk_counter = Counter(
        alert["risk"]
        for alert in alerts
    )

    high = risk_counter.get("HIGH", 0)
    medium = risk_counter.get("MEDIUM", 0)
    low = risk_counter.get("LOW", 0)
    info = risk_counter.get("INFO", 0)
    critical = risk_counter.get("CRITICAL", 0)

    if critical > 0:
        status = "CRITICAL"
    elif high > 0:
        status = "FAILED"
    elif medium > 0 or low > 0:
        status = "WARNING"
    else:
        status = "PASSED"

    sites = data.get("site", [])

    total_instances = sum(
        alert["count"]
        for alert in alerts
    )

    report = {
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(),

        "tool": "zap",

        "stage": "DAST — OWASP ZAP",

        "status": status,

        "zap": {
            "version": data.get("@version"),
            "program": data.get("@programName"),
            "generated": data.get("@generated")
        },

        "summary": {
            "sites": len(sites),
            "alerts": len(alerts),
            "instances": total_instances,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info
        },

        "sites": [
            {
                "name": site.get("@name"),
                "host": site.get("@host"),
                "port": site.get("@port"),
                "ssl": site.get("@ssl")
            }
            for site in sites
        ],

        "alerts": alerts
    }

    with open(
        OUTPUT_FILE,
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
