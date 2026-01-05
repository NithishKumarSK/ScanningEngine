import os
from datetime import datetime

NMAP_ARGUMENTS = "-sV --script vuln"


def log(message: str, level: str = "INFO"):
    print(f"[{datetime.utcnow().isoformat()}] [{level}] {message}")


def sanitize_filename(name: str) -> str:
    return (
        name.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )


def ensure_results_folder():
    os.makedirs("results", exist_ok=True)
