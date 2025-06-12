import subprocess
import ipaddress
import socket
import re
from rich.console import Console

console = Console()

def extract_version(service_name, details_str):
    version = None
    if not details_str:
        return None
    markers_to_cut = [
        "ALERTA DE SEGURANÇA:", "INFO SEGURANÇA:",
        "INFO NMAP -SV:", "INFO NVD:", "INFO NSE FALLBACK:", "INFO NSE:"
    ]
    end_of_original_details = len(details_str)
    for marker in markers_to_cut:
        idx = details_str.upper().find(marker)
        if idx != -1:
            end_of_original_details = min(end_of_original_details, idx)
    original_details = details_str[:end_of_original_details].strip()
    service_name_upper = service_name.upper()
    if not original_details:
        return None
    if "SSH" in service_name_upper:
        m = re.search(r"OpenSSH[_\s]([\w\d\.\-p]+)", original_details, re.IGNORECASE)
        if m:
            version = m.group(1)
    elif "FTP" in service_name_upper:
        m = re.search(r"vsFTPd\s+([\w\d\.\-]+)", original_details, re.IGNORECASE)
        if m:
            version = m.group(1)
    elif "HTTP" in service_name_upper:
        m = re.search(r"Apache/([\d\w\.\-]+)", original_details, re.IGNORECASE)
        if m:
            version = m.group(1)
    elif "MYSQL" in service_name_upper:
        if re.fullmatch(r"[\w\d\.\-]+(?:-[\w\d\.\-]+)*", original_details) and \
                len(original_details.split('.')) >= 2 and len(original_details) < 30:
            version = original_details
    elif "VNC" in service_name_upper:
        m = re.search(r"RFB\s+([\d\.]+)", original_details, re.IGNORECASE)
        if m:
            version = m.group(1)
    elif "POSTGRESQL" in service_name_upper:
        m = re.search(r'(\d+\.\d+\.\d+)(?:\s*-\s*(\d+\.\d+\.\d+))?', original_details)
        if m:
            version = m.group(2) if m.group(2) else m.group(1)
    return version

def validate_input(target):
    try:
        ipaddress.ip_network(target, strict=False)
        return "network"
    except ValueError:
        pass
    try:
        ipaddress.ip_address(target)
        return "host"
    except ValueError:
        pass
    try:
        socket.gethostbyname(target)
        return "url"
    except socket.gaierror:
        console.print(f"[red][!] Erro: Alvo '{target}' inválido.[/red]")
        return None

def check_nmap_installed():
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, check=True, text=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
