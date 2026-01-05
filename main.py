import sys
from datetime import datetime
from scanner import scan_target
from vulnerability import enrich_hosts_with_vulnerabilities
from report import generate_report
from utils import log, NMAP_ARGUMENTS


def main():
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        target = input("Enter IP / Domain / Website: ").strip()

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


if __name__ == "__main__":
    main()
