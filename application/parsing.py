import re
import xml.etree.ElementTree as ET
from rich.console import Console
from utils import extract_version

console = Console()

def parse_banner_scan_report_content(file_content):
    lines = file_content.splitlines()
    parsed_data = []
    current_host_info = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("# Varredura de Rede Detalhada para:"):
            continue
        host_match = re.match(r"Host:\s*(\S+)", line)
        if host_match:
            if current_host_info:
                parsed_data.append(current_host_info)
            current_host_info = {"host": host_match.group(1), "services": []}
            continue
        if not current_host_info:
            continue
        no_services_match = re.match(r"Services:\s*(Nenhuma porta aberta.*)", line)
        if no_services_match:
            current_host_info["services"] = no_services_match.group(1).strip()
            continue
        service_line_match = re.match(r"-\s*(\d+)/(tcp|udp):\s*([^:]+?):\s*(.*)", line)
        if service_line_match:
            port, protocol = service_line_match.group(1), service_line_match.group(2)
            service_name_from_prefix = service_line_match.group(3).strip()
            full_details_with_notes = service_line_match.group(4).strip()
            service_name_match_in_prefix = re.match(r"(\w[\w\s\(\)-]+?)(?:\s*\(Porta \d+\))?$",
                                                    service_name_from_prefix)
            service_name_actual = service_name_match_in_prefix.group(
                1).strip() if service_name_match_in_prefix else service_name_from_prefix
            details_for_version_extraction = full_details_with_notes
            if service_name_actual.upper() == "MYSQL" and not full_details_with_notes:
                if i < len(lines):
                    next_line_content = lines[i].strip()
                    if next_line_content and not next_line_content.startswith("- ") and \
                            not next_line_content.startswith("Host:") and not next_line_content.startswith("Services:"):
                        full_details_with_notes = next_line_content
                        details_for_version_extraction = full_details_with_notes
                        i += 1
            version = extract_version(service_name_actual, details_for_version_extraction)
            service_entry = {"port": port, "protocol": protocol, "service_name": service_name_actual,
                             "details": full_details_with_notes}
            if version:
                service_entry["version"] = version
            if isinstance(current_host_info["services"], str):
                current_host_info["services"] = []
            current_host_info["services"].append(service_entry)
    if current_host_info:
        parsed_data.append(current_host_info)
    return parsed_data

def parse_nmap_xml_output(xml_output):
    open_ports = []
    try:
        root = ET.fromstring(xml_output)
        for host_element in root.findall('host'):
            status_element = host_element.find('status')
            if status_element is None or status_element.get('state') != 'up':
                continue
            ports_element = host_element.find('ports')
            if ports_element is not None:
                for port_element in ports_element.findall('port'):
                    state_element = port_element.find('state')
                    if state_element is not None and state_element.get('state') == 'open':
                        open_ports.append((port_element.get('portid'), port_element.get('protocol')))
    except ET.ParseError as e:
        console.print(f"[yellow][!] Aviso: Parse XML (portas): {e}[/yellow]")
    return open_ports

def parse_nmap_sv_xml_details(xml_output_sv):
    service_details = {}
    script_outputs = {}
    try:
        root = ET.fromstring(xml_output_sv)
        host_node = root.find("host")
        if host_node is None:
            return {"error": "Host node not found in Nmap XML output."}
        port_node = host_node.find(".//port")
        if port_node is not None:
            service_node = port_node.find("service")
            if service_node is not None:
                service_details["nmap_service_name"] = service_node.get("name")
                service_details["product"] = service_node.get("product")
                service_details["version"] = service_node.get("version")
                service_details["extrainfo"] = service_node.get("extrainfo")
                service_details["ostype"] = service_node.get("ostype")
                cpe_nodes = service_node.findall("cpe")
                if cpe_nodes:
                    service_details["cpes"] = [cpe.text for cpe in cpe_nodes if cpe.text]

            for script_node in port_node.findall("script"):
                script_id, script_output = script_node.get("id"), script_node.get("output")
                if script_id and script_output:
                    script_outputs[script_id] = script_output.strip()
            if script_outputs:
                service_details["script_outputs"] = script_outputs
    except ET.ParseError as e:
        service_details["error"] = f"XML Parse Error: {e}"
    return service_details
