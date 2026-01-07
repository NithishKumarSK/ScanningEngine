# import sys
# from datetime import datetime
# from scanner import scan_target
# from vulnerability import enrich_hosts_with_vulnerabilities
# from report import generate_report
# from utils import log, NMAP_ARGUMENTS


# def main():
#     if len(sys.argv) == 2:
#         target = sys.argv[1]
#     else:
#         target = input("Enter IP / Domain / Website: ").strip()

#     log(f"Scan started for target: {target}", "INFO")

#     hosts = scan_target(target)
#     hosts = enrich_hosts_with_vulnerabilities(hosts)

#     final_result = {
#         "timestamp": datetime.utcnow().isoformat(),
#         "command": f"nmap {NMAP_ARGUMENTS} -oX -",
#         "hosts": hosts,
#         "target": target
#     }

#     generate_report(final_result, target)
#     log("Scan completed successfully", "INFO")


# if __name__ == "__main__":
#     main()



import sys
import os
import json
from datetime import datetime
from scanner import scan_target
from vulnerability import enrich_hosts_with_vulnerabilities
from report import generate_report
from utils import log, NMAP_ARGUMENTS

# =========================
# Backend API Imports
# =========================
from fastapi import FastAPI, HTTPException
import uvicorn

RESULTS_DIR = "results"
app = FastAPI(title="Cyber Risk & Threat Intelligence API")


# =========================
# Helper Functions (API)
# =========================
def load_scan_result(target: str):
    file_path = os.path.join(RESULTS_DIR, f"{target}.json")
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Scan result not found")
    with open(file_path, "r") as f:
        return json.load(f)


def build_dashboard_summary(scan_data: dict):
    total = 0
    severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for host in scan_data.get("hosts", {}).values():
        for service in host.get("services", []):
            for vuln in service.get("vulnerabilities", []):
                total += 1
                sev = vuln.get("severity", "").upper()
                if sev in severity_count:
                    severity_count[sev] += 1

    overall_risk = "INFO"
    if severity_count["HIGH"] > 0:
        overall_risk = "HIGH"
    elif severity_count["MEDIUM"] > 0:
        overall_risk = "MEDIUM"
    elif severity_count["LOW"] > 0:
        overall_risk = "LOW"

    return {
        "target": scan_data.get("target"),
        "timestamp": scan_data.get("timestamp"),
        "total_vulnerabilities": total,
        "high": severity_count["HIGH"],
        "medium": severity_count["MEDIUM"],
        "low": severity_count["LOW"],
        "overall_risk": overall_risk
    }


# =========================
# API Endpoints
# =========================
@app.get("/api/threat-intel/{target}")
def threat_intelligence(target: str):
    """
    Returns full, lossless scan intelligence for a target
    """
    return load_scan_result(target)


@app.get("/api/dashboard/{target}")
def dashboard_data(target: str):
    """
    Returns aggregated dashboard-ready metrics for a target
    """
    scan_data = load_scan_result(target)
    return build_dashboard_summary(scan_data)


# =========================
# Existing Scan Logic (UNCHANGED)
# =========================
def run_scan(target: str):
    log(f"Scan started for target: {target}", "INFO")

    hosts = scan_target(target)
    hosts = enrich_hosts_with_vulnerabilities(hosts)

    final_result = {
        "timestamp": datetime.utcnow().isoformat(),
        "command": f"nmap {NMAP_ARGUMENTS} -oX -",
        "hosts": hosts,
        "target": target
    }

    generate_report(final_result, target)
    log("Scan completed successfully", "INFO")


# =========================
# Entry Point
# =========================
def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--api":
        log("Starting Backend API Server", "INFO")
        uvicorn.run(app, host="0.0.0.0", port=8000)
        return

    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        target = input("Enter IP / Domain / Website: ").strip()

    run_scan(target)


if __name__ == "__main__":
    main()
