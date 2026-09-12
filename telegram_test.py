import os
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")


def send_telegram(
    application,
    environment,
    pipeline,
    stage,
    status,
    summary,
    business_impact,
    technical_details,
    next_step=None,
    severity=None
):
    """
    Envoie une notification DevSecOps professionnelle sur Telegram.
    """

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN ou TELEGRAM_CHAT_ID manquant dans .env"
        )

    status_config = {
        "SUCCESS": "🟢",
        "INFO": "🔵",
        "WARNING": "🟠",
        "FAILED": "🔴",
        "CRITICAL": "⚫"
    }

    icon = status_config.get(status.upper(), "🔵")

    timestamp = datetime.now(timezone.utc).strftime(
        "%d/%m/%Y %H:%M UTC"
    )

    message = f"""
{icon} DEVSECOPS — {status.upper()}

Application : {application}
Environnement : {environment}
Pipeline : #{pipeline}
Étape : {stage}
Statut : {status.upper()}
"""

    if severity:
        message += f"Priorité : {severity}\n"

    message += f"""
━━━━━━━━━━━━━━━━━━━━

📋 RÉSUMÉ
{summary}

💼 IMPACT BUSINESS
{business_impact}

🛡️ ANALYSE IT / SÉCURITÉ
{technical_details}
"""

    if next_step:
        message += f"""
➡️ PROCHAINE ACTION
{next_step}
"""

    message += f"""
━━━━━━━━━━━━━━━━━━━━
⏱️ {timestamp}
"""

    url = (
        f"https://api.telegram.org/"
        f"bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    )

    response = requests.post(
        url,
        data={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message.strip()
        },
        timeout=10
    )

    response.raise_for_status()

    result = response.json()

    if not result.get("ok"):
        raise RuntimeError(
            f"Telegram API error: {result}"
        )

    return result


if __name__ == "__main__":

    send_telegram(
        application="TechShop",
        environment="Development",
        pipeline=1,
        stage="Tests automatisés",
        status="SUCCESS",
        summary=(
            "Les tests fonctionnels de l'application "
            "ont été exécutés avec succès."
        ),
        business_impact=(
            "Aucun blocage identifié. "
            "L'application peut poursuivre son cycle de livraison."
        ),
        technical_details=(
            "Tests exécutés : 5\n"
            "Tests réussis : 5\n"
            "Tests échoués : 0"
        ),
        next_step="Analyse SAST — Semgrep"
    )

    print("Notification Telegram envoyée avec succès.")
