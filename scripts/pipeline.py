#!/usr/bin/env python3

import json
import os
import subprocess
import sys
import time
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
SCRIPTS_DIR = BASE_DIR / "scripts"

REPORTS_DIR.mkdir(exist_ok=True)


def run_command(command, description, allow_failure=False):
    print()
    print("=" * 70)
    print(f"▶ {description}")
    print("=" * 70)

    start = time.time()

    try:
        result = subprocess.run(
            command,
            cwd=BASE_DIR,
            text=True,
            capture_output=True
        )

        duration = round(time.time() - start, 2)

        print(result.stdout)

        if result.stderr:
            print(result.stderr, file=sys.stderr)

        print(f"Durée : {duration}s")
        print(f"Exit code : {result.returncode}")

        if result.returncode != 0 and not allow_failure:
            print(f"❌ Échec : {description}")
            return False

        return True

    except Exception as exc:
        print(f"❌ Erreur d'exécution : {exc}")
        return False


def notify(report):
    print()
    print(f"📨 Notification : {report}")

    return run_command(
        [
            sys.executable,
            str(SCRIPTS_DIR / "notify.py"),
            str(REPORTS_DIR / report)
        ],
        f"Notification Telegram — {report}",
        allow_failure=True
    )


def stage_pytest():
    print("\n🧪 STAGE 1 — TESTS AUTOMATISÉS")

    success = run_command(
        [
            sys.executable,
            str(SCRIPTS_DIR / "pytest_report.py")
        ],
        "Pytest"
    )

    if Path(REPORTS_DIR / "pytest.json").exists():
        notify("pytest.json")

    return success


def stage_semgrep():
    print("\n🔎 STAGE 2 — SAST / SEMGREP")

    success = run_command(
        [
            sys.executable,
            str(SCRIPTS_DIR / "semgrep_report.py")
        ],
        "Semgrep SAST"
    )

    if Path(REPORTS_DIR / "semgrep_report.json").exists():
        notify("semgrep_report.json")

    return success


def stage_trivy():
    print("\n🛡️ STAGE 3 — SCA / CONTAINER SECURITY")

    success_fs = run_command(
        [
            "trivy",
            "fs",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--output",
            str(REPORTS_DIR / "trivy-fs.json"),
            "app/"
        ],
        "Trivy — filesystem",
        allow_failure=True
    )

    print("\n🐳 Construction de l'image Docker")

    success_build = run_command(
        [
            "docker",
            "build",
            "-t",
            "devsecops-lab-app:latest",
            "."
        ],
        "Docker build"
    )

    if not success_build:
        return False

    success_image = run_command(
        [
            "sudo",
            "trivy",
            "image",
            "--scanners",
            "vuln",
            "--format",
            "json",
            "--output",
            str(REPORTS_DIR / "trivy-image.json"),
            "devsecops-lab-app:latest"
        ],
        "Trivy — container image",
        allow_failure=True
    )

    success_report = run_command(
        [
            sys.executable,
            str(SCRIPTS_DIR / "trivy_report.py")
        ],
        "Génération du rapport Trivy"
    )

    if Path(REPORTS_DIR / "trivy.json").exists():
        notify("trivy.json")

    return success_fs and success_build and success_image and success_report


def stage_deploy():
    print("\n🚀 STAGE 4 — DÉPLOIEMENT")

    success = run_command(
        [
            "docker",
            "compose",
            "up",
            "-d",
            "--build"
        ],
        "Docker Compose deployment"
    )

    if not success:
        return False

    print("\n🔍 Vérification de l'application")

    time.sleep(5)

    health = run_command(
        [
            "curl",
            "-fsS",
            "http://127.0.0.1/health"
        ],
        "Health check"
    )

    return health


def stage_zap():
    print("\n🕷️ STAGE 5 — DAST / OWASP ZAP")

    success_zap = run_command(
        [
            "sudo",
            "docker",
            "run",
            "--rm",
            "--network",
            "host",
            "-v",
            f"{REPORTS_DIR}:/zap/wrk:rw",
            "zaproxy/zap-stable",
            "zap-baseline.py",
            "-t",
            "http://127.0.0.1",
            "-J",
            "zap.json",
            "-r",
            "zap.html"
        ],
        "OWASP ZAP baseline scan",
        allow_failure=True
    )

    success_report = run_command(
        [
            sys.executable,
            str(SCRIPTS_DIR / "zap_report.py")
        ],
        "Génération du rapport ZAP"
    )

    if Path(REPORTS_DIR / "zap_report.json").exists():
        notify("zap_report.json")

    return success_zap and success_report


def show_summary(results):
    print()
    print("=" * 70)
    print("📊 RÉSUMÉ DU PIPELINE")
    print("=" * 70)

    for stage, status in results.items():
        symbol = "🟢" if status else "🔴"
        print(f"{symbol} {stage}")

    print("=" * 70)


def main():
    print()
    print("=" * 70)
    print("🚀 DEVSECOPS SECURITY PIPELINE")
    print("=" * 70)
    print(f"Projet : {BASE_DIR}")
    print(f"Heure  : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    results = {}

    results["Tests automatisés"] = stage_pytest()

    if not results["Tests automatisés"]:
        show_summary(results)
        return 1

    results["SAST — Semgrep"] = stage_semgrep()

    if not results["SAST — Semgrep"]:
        show_summary(results)
        return 1

    results["SCA / Container — Trivy"] = stage_trivy()

    if not results["SCA / Container — Trivy"]:
        show_summary(results)
        return 1

    results["Déploiement"] = stage_deploy()

    if not results["Déploiement"]:
        show_summary(results)
        return 1

    results["DAST — OWASP ZAP"] = stage_zap()

    show_summary(results)

    if all(results.values()):
        print("\n🟢 PIPELINE TERMINÉ AVEC SUCCÈS")
        return 0

    print("\n🟠 PIPELINE TERMINÉ AVEC DES AVERTISSEMENTS")
    return 1


if __name__ == "__main__":
    sys.exit(main())
