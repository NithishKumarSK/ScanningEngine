import json
import os
from utils import sanitize_filename, ensure_results_folder, log


def generate_report(data: dict, target: str):
    ensure_results_folder()
    filename = f"{sanitize_filename(target)}.json"
    path = os.path.join("results", filename)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(json.dumps(data, indent=2))
    print(f"\n[+] Scan results saved as: {filename}")
    log(f"Report saved successfully: {path}", "INFO")
