# import os
# import json
# from fastapi import FastAPI, HTTPException

# RESULTS_DIR = "results"

# app = FastAPI(
#     title="Cyber Risk & Threat Intelligence API",
#     version="1.0"
# )


# def load_scan_result(target: str):
#     filename = f"{target}.json"
#     filepath = os.path.join(RESULTS_DIR, filename)

#     if not os.path.exists(filepath):
#         raise HTTPException(status_code=404, detail="Scan result not found")

#     with open(filepath, "r", encoding="utf-8") as f:
#         return json.load(f)


# @app.get("/api/threat-intel/{target}")
# def threat_intelligence(target: str):
#     """
#     Returns full, lossless scan intelligence for a target.
#     """
#     data = load_scan_result(target)
#     return data


# @app.get("/api/dashboard/{target}")
# def dashboard_summary(target: str):
#     """
#     Returns aggregated, dashboard-ready metrics for a target.
#     """
#     data = load_scan_result(target)

#     total_vulns = 0
#     severity_count = {
#         "CRITICAL": 0,
#         "HIGH": 0,
#         "MEDIUM": 0,
#         "LOW": 0
#     }

#     for host in data.get("hosts", {}).values():
#         for service in host.get("services", []):
#             for vuln in service.get("vulnerabilities", []):
#                 total_vulns += 1
#                 sev = vuln.get("severity", "").upper()
#                 if sev in severity_count:
#                     severity_count[sev] += 1

#     dashboard_data = {
#         "target": data.get("target"),
#         "last_scan_time": data.get("timestamp"),
#         "total_vulnerabilities": total_vulns,
#         "severity_breakdown": severity_count,
#         "overall_risk": max(
#             severity_count,
#             key=lambda k: severity_count[k]
#         ) if total_vulns > 0 else "INFO"
#     }

#     return dashboard_data


import os
import json
from fastapi import FastAPI, HTTPException
from typing import Dict

RESULTS_DIR = "results"

app = FastAPI(
    title="Cyber Risk & Threat Intelligence API",
    version="1.0"
)


def load_result(target: str) -> Dict:
    file_path = os.path.join(RESULTS_DIR, f"{target}.json")

    if not os.path.exists(file_path):
        raise HTTPException(
            status_code=404,
            detail="Scan result not found for given target"
        )

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


# ===============================
# Threat Intelligence Endpoint
# ===============================
@app.get("/api/threat-intel/{target}", tags=["Threat Intelligence"])
def get_threat_intelligence(target: str):
    """
    Returns FULL stored scan result (lossless).
    """
    return load_result(target)


# ===============================
# Dashboard Endpoint
# ===============================
@app.get("/api/dashboard/{target}")
def get_dashboard_summary(target: str):
    file_path = os.path.join(RESULTS_DIR, f"{target}.json")

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Scan result not found")

    with open(file_path, "r") as f:
        data = json.load(f)

    total_hosts = len(data.get("hosts", {}))
    open_ports = 0
    total_vulnerabilities = 0

    risk_distribution = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0
    }

    overall_risk = "LOW"

    # 🔥 FIX STARTS HERE
    for _, host_data in data.get("hosts", {}).items():
        for service in host_data.get("services", []):
            if service.get("state") == "open":
                open_ports += 1

            for vuln in service.get("vulnerabilities", []):
                total_vulnerabilities += 1
                severity = vuln.get("severity", "LOW")
                risk_distribution[severity] += 1

    # Determine overall risk (highest severity wins)
    if risk_distribution["CRITICAL"] > 0:
        overall_risk = "CRITICAL"
    elif risk_distribution["HIGH"] > 0:
        overall_risk = "HIGH"
    elif risk_distribution["MEDIUM"] > 0:
        overall_risk = "MEDIUM"

    return {
        "target": target,
        "scan_time": data.get("timestamp"),
        "total_hosts": total_hosts,
        "open_ports": open_ports,
        "total_vulnerabilities": total_vulnerabilities,
        "risk_distribution": risk_distribution,
        "overall_risk": overall_risk
    }

