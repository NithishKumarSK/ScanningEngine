import subprocess
import xml.etree.ElementTree as ET
from utils import log, NMAP_ARGUMENTS


def scan_target(target: str) -> dict:
    log(f"Starting Nmap scan for {target}", "INFO")

    command = [
        "nmap",
        "-sV",
        "--script", "vuln",
        "-oX", "-",
        target
    ]

    try:
        xml_output = subprocess.check_output(
            command,
            stderr=subprocess.DEVNULL,
            text=True
        )
    except Exception as e:
        log(f"Nmap execution failed: {e}", "ERROR")
        raise RuntimeError("Nmap scan failed")

    return _parse_nmap_xml(xml_output)


def _parse_nmap_xml(xml_data: str) -> dict:
    root = ET.fromstring(xml_data)
    hosts = {}

    for host in root.findall("host"):
        address = host.find("address").attrib.get("addr")
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.attrib.get("name") if hostname_el is not None else ""

        services = []

        for port in host.findall(".//port"):
            state = port.find("state").attrib.get("state")
            service_el = port.find("service")

            service_data = {
                "port": int(port.attrib["portid"]),
                "protocol": port.attrib["protocol"],
                "state": state,
                "service": service_el.attrib.get("name", "") if service_el is not None else "",
                "product": service_el.attrib.get("product", "") if service_el is not None else "",
                "version": service_el.attrib.get("version", "") if service_el is not None else "",
                "vulnerabilities": []
            }

            for script in port.findall("script"):
                if "vuln" in script.attrib.get("id", ""):
                    service_data["vulnerabilities"].append({
                        "script": script.attrib.get("id"),
                        "output": script.attrib.get("output", "")
                    })

            services.append(service_data)

        hosts[address] = {
            "hostname": hostname,
            "state": "up",
            "services": services
        }

    return hosts
