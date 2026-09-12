#!/usr/bin/env python3

import json
import os
import sys

import requests
from dotenv import load_dotenv


load_dotenv()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


# ============================================================
# TELEGRAM
# ============================================================

def send_message(message):

    if not TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN absent")

    if not CHAT_ID:
        raise RuntimeError("TELEGRAM_CHAT_ID absent")

    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

    response = requests.post(
        url,
        data={
            "chat_id": CHAT_ID,
            "text": message
        },
        timeout=10
    )

    response.raise_for_status()


# ============================================================
# PYTEST
# ============================================================

def format_pytest(report):

    tests = report["tests"]

    if report["status"] == "PASSED":
        icon = "🟢"
        status = "SUCCESS"

        impact = (
            "Les tests fonctionnels sont validés. "
            "Le pipeline peut poursuivre son exécution."
        )

    else:
        icon = "🔴"
        status = "FAILED"

        impact = (
            "Des tests ont échoué. "
            "La livraison doit être bloquée jusqu'à correction."
        )

    return f"""\
{icon} DEVSECOPS — TESTS AUTOMATISÉS

Application : TechShop
Environnement : Development
Étape : Automated Tests
Statut : {status}

━━━━━━━━━━━━━━━━━━━━

🧪 RÉSULTATS

Tests collectés : {tests["collected"]}
Tests réussis   : {tests["passed"]}
Tests échoués   : {tests["failed"]}
Tests ignorés   : {tests["skipped"]}
Erreurs         : {tests["errors"]}

Durée : {report["duration_seconds"]}s

━━━━━━━━━━━━━━━━━━━━

💼 IMPACT BUSINESS

{impact}

━━━━━━━━━━━━━━━━━━━━

➡️ PROCHAINE ÉTAPE

SAST — Semgrep
"""


# ============================================================
# SEMGREP
# ============================================================

def format_semgrep(report):

    summary = report["summary"]
    scan = report["scan"]
    performance = report.get("performance", {})

    findings = summary["findings"]

    duration = performance.get(
        "duration_seconds",
        "N/A"
    )

    if report["status"] == "PASSED":

        icon = "🟢"
        status = "SUCCESS"

        impact = (
            "Aucun problème de sécurité détecté. "
            "Le code peut poursuivre le pipeline."
        )

    elif report["status"] == "WARNING":

        icon = "🟠"
        status = "WARNING"

        impact = (
            "Des problèmes de sécurité ont été détectés. "
            "Une analyse et une décision de sécurité sont nécessaires."
        )

    else:

        icon = "🔴"
        status = "FAILED"

        impact = (
            "Le contrôle SAST a rencontré une erreur. "
            "Le pipeline doit être vérifié avant de poursuivre."
        )

    message = f"""\
{icon} DEVSECOPS — CONTRÔLE SAST

Application : TechShop
Environnement : Development
Étape : SAST — Semgrep
Statut : {status}

━━━━━━━━━━━━━━━━━━━━

🛡️ ANALYSE DE SÉCURITÉ

Findings : {findings}
ERROR    : {summary["error"]}
WARNING  : {summary["warning"]}
INFO     : {summary["info"]}
UNKNOWN  : {summary["unknown"]}

Fichiers analysés : {scan["files_count"]}
Moteur : {scan["engine"]}
Version : {scan["version"]}

Durée : {duration}s

━━━━━━━━━━━━━━━━━━━━

💼 IMPACT BUSINESS

{impact}

"""

    if findings:

        message += "🚨 FINDINGS DÉTECTÉS\n\n"

        for index, finding in enumerate(
            report["findings"][:5],
            1
        ):

            message += (
                f"{index}. {finding['severity']}\n"
                f"   Règle : {finding['rule']}\n"
                f"   Fichier : {finding['path']}\n"
                f"   Ligne : {finding['line']}\n"
                f"   Message : {finding['message']}\n\n"
            )

        if findings > 5:

            message += (
                f"... et {findings - 5} finding(s) "
                "supplémentaire(s).\n\n"
            )

    message += "━━━━━━━━━━━━━━━━━━━━\n\n"

    if report["status"] == "PASSED":

        message += """\
➡️ PROCHAINE ÉTAPE

SCA / Container Scan — Trivy
"""

    elif report["status"] == "WARNING":

        message += """\
➡️ DÉCISION

Évaluer les findings avant de poursuivre le pipeline.
"""

    else:

        message += """\
🛑 ACTION

Vérifier l'exécution de Semgrep avant de poursuivre.
"""

    return message


# ============================================================
# TRIVY
# ============================================================

def format_trivy(report):

    summary = report.get("summary", {})
    scans = report.get("scans", {})
    image = scans.get("container_image", {})
    filesystem = scans.get("filesystem", {})

    total = summary.get(
        "total_vulnerabilities",
        0
    )

    critical = summary.get(
        "critical",
        0
    )

    high = summary.get(
        "high",
        0
    )

    medium = summary.get(
        "medium",
        0
    )

    low = summary.get(
        "low",
        0
    )

    unknown = summary.get(
        "unknown",
        0
    )

    scanner_errors = summary.get(
        "scanner_errors",
        0
    )

    status = report.get(
        "status",
        "UNKNOWN"
    )

    status_icons = {
        "PASSED": "🟢",
        "WARNING": "🟠",
        "FAILED": "🔴",
        "CRITICAL": "⚫"
    }

    icon = status_icons.get(
        status,
        "🔵"
    )

    image_artifact = image.get(
        "artifact",
        "N/A"
    )

    image_os = image.get(
        "os",
        {}
    )

    os_name = image_os.get(
        "Name",
        ""
    )

    os_family = image_os.get(
        "Family",
        ""
    )

    trivy_version = image.get(
        "trivy_version",
        "N/A"
    )

    lines = [
        f"{icon} {status} — SCA + CONTAINER SECURITY",
        "",
        "🔍 Scanner : Trivy",
        "",
        "📦 SCA — DÉPENDANCES",
        f"Vulnérabilités : "
        f"{filesystem.get('total_vulnerabilities', 'N/A')}",
        "",
        "🐳 CONTAINER SECURITY",
        f"Image : {image_artifact}",
        f"OS : {os_family} {os_name}".strip(),
        f"Version Trivy : {trivy_version}",
        "",
        f"📊 TOTAL CONSOLIDÉ : {total}",
        "",
        f"⚫ Critical : {critical}",
        f"🔴 High     : {high}",
        f"🟠 Medium   : {medium}",
        f"🟢 Low      : {low}",
        f"⚪ Unknown  : {unknown}",
        "",
        f"⚙️ Erreurs scanner : {scanner_errors}"
    ]

    vulnerabilities = report.get(
        "vulnerabilities",
        []
    )

    priority = [
        v for v in vulnerabilities
        if v.get("severity") in (
            "CRITICAL",
            "HIGH"
        )
    ]

    priority = priority[:5]

    if priority:

        lines.extend([
            "",
            "🚨 PRINCIPAUX RISQUES"
        ])

        for vuln in priority:

            vuln_id = vuln.get(
                "vulnerability_id",
                "N/A"
            )

            package = vuln.get(
                "package",
                "N/A"
            )

            installed = vuln.get(
                "installed_version",
                "N/A"
            )

            fixed = vuln.get(
                "fixed_version"
            )

            if fixed:
                version_info = (
                    f"{installed} → {fixed}"
                )
            else:
                version_info = installed

            severity = vuln.get(
                "severity",
                "UNKNOWN"
            )

            lines.append(
                f"• {severity} | {vuln_id} | "
                f"{package} ({version_info})"
            )

    if critical > 0 or high > 0:

        impact = (
            "Des composants vulnérables Critical/High ont été "
            "détectés dans les dépendances ou l'image. "
            "Une exploitation pourrait compromettre la "
            "confidentialité, l'intégrité ou la disponibilité "
            "du service."
        )

        action = (
            "Prioriser les vulnérabilités Critical/High, "
            "mettre à jour les composants concernés et "
            "reconstruire l'image avant déploiement."
        )

    elif total > 0:

        impact = (
            "Des vulnérabilités connues sont présentes dans "
            "les composants analysés. Le risque doit être "
            "évalué selon l'exposition réelle du service."
        )

        action = (
            "Examiner les vulnérabilités détectées et appliquer "
            "les mises à jour disponibles."
        )

    else:

        impact = (
            "Aucune vulnérabilité connue n'a été détectée "
            "dans les composants analysés."
        )

        action = (
            "Maintenir une surveillance régulière des "
            "dépendances et de l'image."
        )

    lines.extend([
        "",
        "💼 IMPACT MÉTIER",
        impact,
        "",
        "🛠️ ACTION RECOMMANDÉE",
        action,
        "",
        f"📌 État du contrôle : {icon} {status}"
    ])

    return "\n".join(lines)


# ============================================================
# OWASP ZAP
# ============================================================

def format_zap(report):

    summary = report.get(
        "summary",
        {}
    )

    zap = report.get(
        "zap",
        {}
    )

    sites = report.get(
        "sites",
        []
    )

    status = report.get(
        "status",
        "UNKNOWN"
    )

    status_icons = {
        "PASSED": "🟢",
        "WARNING": "🟠",
        "FAILED": "🔴",
        "CRITICAL": "⚫"
    }

    icon = status_icons.get(
        status,
        "🔵"
    )

    if sites:
        site_name = sites[0].get(
            "name",
            "N/A"
        )
    else:
        site_name = "N/A"

    message = f"""\
{icon} DEVSECOPS — DAST / OWASP ZAP

Application : TechShop
Environnement : Development
Étape : DAST — OWASP ZAP
Statut : {status}

━━━━━━━━━━━━━━━━━━━━

🔍 ANALYSE DYNAMIQUE

Scanner : OWASP ZAP
Version : {zap.get("version", "N/A")}
Site : {site_name}

━━━━━━━━━━━━━━━━━━━━

📊 RÉSULTATS

Alertes    : {summary.get("alerts", 0)}
Instances  : {summary.get("instances", 0)}

⚫ Critical : {summary.get("critical", 0)}
🔴 High     : {summary.get("high", 0)}
🟠 Medium   : {summary.get("medium", 0)}
🟢 Low      : {summary.get("low", 0)}
🔵 Info     : {summary.get("info", 0)}

"""

    alerts = report.get(
        "alerts",
        []
    )

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    alerts = sorted(
        alerts,
        key=lambda x: priority_order.get(
            x.get("risk", "INFO"),
            5
        )
    )

    if alerts:

        message += "🚨 PRINCIPALES ALERTES\n\n"

        for alert in alerts[:5]:

            risk = alert.get(
                "risk",
                "UNKNOWN"
            )

            name = alert.get(
                "name",
                "N/A"
            )

            count = alert.get(
                "count",
                0
            )

            message += (
                f"• {risk} | {name}\n"
                f"  └─ {count} instance(s)\n\n"
            )

        if len(alerts) > 5:

            message += (
                f"... et {len(alerts) - 5} "
                "alerte(s) supplémentaire(s).\n\n"
            )

    medium = summary.get(
        "medium",
        0
    )

    high = summary.get(
        "high",
        0
    )

    critical = summary.get(
        "critical",
        0
    )

    if critical > 0:

        impact = (
            "Des vulnérabilités critiques ont été détectées "
            "sur l'application exposée. Une correction immédiate "
            "est requise avant toute mise en production."
        )

        action = (
            "Bloquer la livraison et corriger les vulnérabilités "
            "Critical avant nouveau déploiement."
        )

    elif high > 0:

        impact = (
            "Des vulnérabilités High ont été détectées. "
            "Elles peuvent présenter un risque important "
            "pour l'application exposée."
        )

        action = (
            "Prioriser la correction des vulnérabilités High "
            "avant mise en production."
        )

    elif medium > 0:

        impact = (
            "Des contrôles de sécurité HTTP doivent être "
            "renforcés. Aucun risque High ou Critical n'a "
            "été détecté lors de ce contrôle."
        )

        action = (
            "Corriger les alertes Medium, puis renforcer "
            "les headers de sécurité associés aux alertes Low."
        )

    else:

        impact = (
            "Aucune vulnérabilité significative n'a été "
            "détectée par le contrôle dynamique."
        )

        action = (
            "Maintenir les contrôles DAST dans le cycle "
            "de développement."
        )

    message += f"""\
━━━━━━━━━━━━━━━━━━━━

💼 IMPACT BUSINESS

{impact}

━━━━━━━━━━━━━━━━━━━━

🛠️ ACTION RECOMMANDÉE

{action}

━━━━━━━━━━━━━━━━━━━━

📌 État du contrôle : {icon} {status}
"""

    return message


# ============================================================
# CHARGEMENT DU RAPPORT
# ============================================================

def load_report(report_file):

    if not os.path.exists(report_file):

        raise FileNotFoundError(
            f"Rapport introuvable : {report_file}"
        )

    with open(
        report_file,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# MAIN
# ============================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage : python scripts/notify.py "
            "<rapport.json>"
        )

        sys.exit(1)

    report_file = sys.argv[1]

    report = load_report(
        report_file
    )

    tool = report.get(
        "tool"
    )

    if tool == "pytest":

        message = format_pytest(
            report
        )

    elif tool == "semgrep":

        message = format_semgrep(
            report
        )

    elif tool == "trivy":

        message = format_trivy(
            report
        )

    elif tool == "zap":

        message = format_zap(
            report
        )

    else:

        raise RuntimeError(
            f"Outil non supporté : {tool}"
        )

    send_message(
        message
    )

    print(
        f"Notification Telegram envoyée : {tool}"
    )


if __name__ == "__main__":
    main()#!/usr/bin/env python3

import json
import os
import sys

import requests
from dotenv import load_dotenv


load_dotenv()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


# ============================================================
# TELEGRAM
# ============================================================

def send_message(message):

    if not TOKEN:
        raise RuntimeError("TELEGRAM_BOT_TOKEN absent")

    if not CHAT_ID:
        raise RuntimeError("TELEGRAM_CHAT_ID absent")

    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"

    response = requests.post(
        url,
        data={
            "chat_id": CHAT_ID,
            "text": message
        },
        timeout=10
    )

    response.raise_for_status()


# ============================================================
# PYTEST
# ============================================================

def format_pytest(report):

    tests = report["tests"]

    if report["status"] == "PASSED":
        icon = "🟢"
        status = "SUCCESS"

        impact = (
            "Les tests fonctionnels sont validés. "
            "Le pipeline peut poursuivre son exécution."
        )

    else:
        icon = "🔴"
        status = "FAILED"

        impact = (
            "Des tests ont échoué. "
            "La livraison doit être bloquée jusqu'à correction."
        )

    return f"""\
{icon} DEVSECOPS — TESTS AUTOMATISÉS

Application : TechShop
Environnement : Development
Étape : Automated Tests
Statut : {status}

━━━━━━━━━━━━━━━━━━━━

🧪 RÉSULTATS

Tests collectés : {tests["collected"]}
Tests réussis   : {tests["passed"]}
Tests échoués   : {tests["failed"]}
Tests ignorés   : {tests["skipped"]}
Erreurs         : {tests["errors"]}

Durée : {report["duration_seconds"]}s

━━━━━━━━━━━━━━━━━━━━

💼 IMPACT BUSINESS

{impact}

━━━━━━━━━━━━━━━━━━━━

➡️ PROCHAINE ÉTAPE

SAST — Semgrep
"""


# ============================================================
# SEMGREP
# ============================================================

def format_semgrep(report):

    summary = report["summary"]
    scan = report["scan"]
    performance = report.get("performance", {})

    findings = summary["findings"]

    duration = performance.get(
        "duration_seconds",
        "N/A"
    )

    if report["status"] == "PASSED":

        icon = "🟢"
        status = "SUCCESS"

        impact = (
            "Aucun problème de sécurité détecté. "
            "Le code peut poursuivre le pipeline."
        )

    elif report["status"] == "WARNING":

        icon = "🟠"
        status = "WARNING"

        impact = (
            "Des problèmes de sécurité ont été détectés. "
            "Une analyse et une décision de sécurité sont nécessaires."
        )

    else:

        icon = "🔴"
        status = "FAILED"

        impact = (
            "Le contrôle SAST a rencontré une erreur. "
            "Le pipeline doit être vérifié avant de poursuivre."
        )

    message = f"""\
{icon} DEVSECOPS — CONTRÔLE SAST

Application : TechShop
Environnement : Development
Étape : SAST — Semgrep
Statut : {status}

━━━━━━━━━━━━━━━━━━━━

🛡️ ANALYSE DE SÉCURITÉ

Findings : {findings}
ERROR    : {summary["error"]}
WARNING  : {summary["warning"]}
INFO     : {summary["info"]}
UNKNOWN  : {summary["unknown"]}

Fichiers analysés : {scan["files_count"]}
Moteur : {scan["engine"]}
Version : {scan["version"]}

Durée : {duration}s

━━━━━━━━━━━━━━━━━━━━

💼 IMPACT BUSINESS

{impact}

"""

    if findings:

        message += "🚨 FINDINGS DÉTECTÉS\n\n"

        for index, finding in enumerate(
            report["findings"][:5],
            1
        ):

            message += (
                f"{index}. {finding['severity']}\n"
                f"   Règle : {finding['rule']}\n"
                f"   Fichier : {finding['path']}\n"
                f"   Ligne : {finding['line']}\n"
                f"   Message : {finding['message']}\n\n"
            )

        if findings > 5:

            message += (
                f"... et {findings - 5} finding(s) "
                "supplémentaire(s).\n\n"
            )

    message += "━━━━━━━━━━━━━━━━━━━━\n\n"

    if report["status"] == "PASSED":

        message += """\
➡️ PROCHAINE ÉTAPE

SCA / Container Scan — Trivy
"""

    elif report["status"] == "WARNING":

        message += """\
➡️ DÉCISION

Évaluer les findings avant de poursuivre le pipeline.
"""

    else:

        message += """\
🛑 ACTION

Vérifier l'exécution de Semgrep avant de poursuivre.
"""

    return message


# ============================================================
# TRIVY
# ============================================================

def format_trivy(report):

    summary = report.get("summary", {})
    scans = report.get("scans", {})
    image = scans.get("container_image", {})
    filesystem = scans.get("filesystem", {})

    total = summary.get(
        "total_vulnerabilities",
        0
    )

    critical = summary.get(
        "critical",
        0
    )

    high = summary.get(
        "high",
        0
    )

    medium = summary.get(
        "medium",
        0
    )

    low = summary.get(
        "low",
        0
    )

    unknown = summary.get(
        "unknown",
        0
    )

    scanner_errors = summary.get(
        "scanner_errors",
        0
    )

    status = report.get(
        "status",
        "UNKNOWN"
    )

    status_icons = {
        "PASSED": "🟢",
        "WARNING": "🟠",
        "FAILED": "🔴",
        "CRITICAL": "⚫"
    }

    icon = status_icons.get(
        status,
        "🔵"
    )

    image_artifact = image.get(
        "artifact",
        "N/A"
    )

    image_os = image.get(
        "os",
        {}
    )

    os_name = image_os.get(
        "Name",
        ""
    )

    os_family = image_os.get(
        "Family",
        ""
    )

    trivy_version = image.get(
        "trivy_version",
        "N/A"
    )

    lines = [
        f"{icon} {status} — SCA + CONTAINER SECURITY",
        "",
        "🔍 Scanner : Trivy",
        "",
        "📦 SCA — DÉPENDANCES",
        f"Vulnérabilités : "
        f"{filesystem.get('total_vulnerabilities', 'N/A')}",
        "",
        "🐳 CONTAINER SECURITY",
        f"Image : {image_artifact}",
        f"OS : {os_family} {os_name}".strip(),
        f"Version Trivy : {trivy_version}",
        "",
        f"📊 TOTAL CONSOLIDÉ : {total}",
        "",
        f"⚫ Critical : {critical}",
        f"🔴 High     : {high}",
        f"🟠 Medium   : {medium}",
        f"🟢 Low      : {low}",
        f"⚪ Unknown  : {unknown}",
        "",
        f"⚙️ Erreurs scanner : {scanner_errors}"
    ]

    vulnerabilities = report.get(
        "vulnerabilities",
        []
    )

    priority = [
        v for v in vulnerabilities
        if v.get("severity") in (
            "CRITICAL",
            "HIGH"
        )
    ]

    priority = priority[:5]

    if priority:

        lines.extend([
            "",
            "🚨 PRINCIPAUX RISQUES"
        ])

        for vuln in priority:

            vuln_id = vuln.get(
                "vulnerability_id",
                "N/A"
            )

            package = vuln.get(
                "package",
                "N/A"
            )

            installed = vuln.get(
                "installed_version",
                "N/A"
            )

            fixed = vuln.get(
                "fixed_version"
            )

            if fixed:
                version_info = (
                    f"{installed} → {fixed}"
                )
            else:
                version_info = installed

            severity = vuln.get(
                "severity",
                "UNKNOWN"
            )

            lines.append(
                f"• {severity} | {vuln_id} | "
                f"{package} ({version_info})"
            )

    if critical > 0 or high > 0:

        impact = (
            "Des composants vulnérables Critical/High ont été "
            "détectés dans les dépendances ou l'image. "
            "Une exploitation pourrait compromettre la "
            "confidentialité, l'intégrité ou la disponibilité "
            "du service."
        )

        action = (
            "Prioriser les vulnérabilités Critical/High, "
            "mettre à jour les composants concernés et "
            "reconstruire l'image avant déploiement."
        )

    elif total > 0:

        impact = (
            "Des vulnérabilités connues sont présentes dans "
            "les composants analysés. Le risque doit être "
            "évalué selon l'exposition réelle du service."
        )

        action = (
            "Examiner les vulnérabilités détectées et appliquer "
            "les mises à jour disponibles."
        )

    else:

        impact = (
            "Aucune vulnérabilité connue n'a été détectée "
            "dans les composants analysés."
        )

        action = (
            "Maintenir une surveillance régulière des "
            "dépendances et de l'image."
        )

    lines.extend([
        "",
        "💼 IMPACT MÉTIER",
        impact,
        "",
        "🛠️ ACTION RECOMMANDÉE",
        action,
        "",
        f"📌 État du contrôle : {icon} {status}"
    ])

    return "\n".join(lines)


# ============================================================
# OWASP ZAP
# ============================================================

def format_zap(report):

    summary = report.get(
        "summary",
        {}
    )

    zap = report.get(
        "zap",
        {}
    )

    sites = report.get(
        "sites",
        []
    )

    status = report.get(
        "status",
        "UNKNOWN"
    )

    status_icons = {
        "PASSED": "🟢",
        "WARNING": "🟠",
        "FAILED": "🔴",
        "CRITICAL": "⚫"
    }

    icon = status_icons.get(
        status,
        "🔵"
    )

    if sites:
        site_name = sites[0].get(
            "name",
            "N/A"
        )
    else:
        site_name = "N/A"

    message = f"""\
{icon} DEVSECOPS — DAST / OWASP ZAP

Application : TechShop
Environnement : Development
Étape : DAST — OWASP ZAP
Statut : {status}

━━━━━━━━━━━━━━━━━━━━

🔍 ANALYSE DYNAMIQUE

Scanner : OWASP ZAP
Version : {zap.get("version", "N/A")}
Site : {site_name}

━━━━━━━━━━━━━━━━━━━━

📊 RÉSULTATS

Alertes    : {summary.get("alerts", 0)}
Instances  : {summary.get("instances", 0)}

⚫ Critical : {summary.get("critical", 0)}
🔴 High     : {summary.get("high", 0)}
🟠 Medium   : {summary.get("medium", 0)}
🟢 Low      : {summary.get("low", 0)}
🔵 Info     : {summary.get("info", 0)}

"""

    alerts = report.get(
        "alerts",
        []
    )

    priority_order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4
    }

    alerts = sorted(
        alerts,
        key=lambda x: priority_order.get(
            x.get("risk", "INFO"),
            5
        )
    )

    if alerts:

        message += "🚨 PRINCIPALES ALERTES\n\n"

        for alert in alerts[:5]:

            risk = alert.get(
                "risk",
                "UNKNOWN"
            )

            name = alert.get(
                "name",
                "N/A"
            )

            count = alert.get(
                "count",
                0
            )

            message += (
                f"• {risk} | {name}\n"
                f"  └─ {count} instance(s)\n\n"
            )

        if len(alerts) > 5:

            message += (
                f"... et {len(alerts) - 5} "
                "alerte(s) supplémentaire(s).\n\n"
            )

    medium = summary.get(
        "medium",
        0
    )

    high = summary.get(
        "high",
        0
    )

    critical = summary.get(
        "critical",
        0
    )

    if critical > 0:

        impact = (
            "Des vulnérabilités critiques ont été détectées "
            "sur l'application exposée. Une correction immédiate "
            "est requise avant toute mise en production."
        )

        action = (
            "Bloquer la livraison et corriger les vulnérabilités "
            "Critical avant nouveau déploiement."
        )

    elif high > 0:

        impact = (
            "Des vulnérabilités High ont été détectées. "
            "Elles peuvent présenter un risque important "
            "pour l'application exposée."
        )

        action = (
            "Prioriser la correction des vulnérabilités High "
            "avant mise en production."
        )

    elif medium > 0:

        impact = (
            "Des contrôles de sécurité HTTP doivent être "
            "renforcés. Aucun risque High ou Critical n'a "
            "été détecté lors de ce contrôle."
        )

        action = (
            "Corriger les alertes Medium, puis renforcer "
            "les headers de sécurité associés aux alertes Low."
        )

    else:

        impact = (
            "Aucune vulnérabilité significative n'a été "
            "détectée par le contrôle dynamique."
        )

        action = (
            "Maintenir les contrôles DAST dans le cycle "
            "de développement."
        )

    message += f"""\
━━━━━━━━━━━━━━━━━━━━

💼 IMPACT BUSINESS

{impact}

━━━━━━━━━━━━━━━━━━━━

🛠️ ACTION RECOMMANDÉE

{action}

━━━━━━━━━━━━━━━━━━━━

📌 État du contrôle : {icon} {status}
"""

    return message


# ============================================================
# CHARGEMENT DU RAPPORT
# ============================================================

def load_report(report_file):

    if not os.path.exists(report_file):

        raise FileNotFoundError(
            f"Rapport introuvable : {report_file}"
        )

    with open(
        report_file,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# MAIN
# ============================================================
