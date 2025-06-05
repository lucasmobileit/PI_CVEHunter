import subprocess
import os
import sys
import argparse
import time
import ipaddress
import socket
from rich.console import Console
from rich.table import Table
from rich.progress import track
import ssl
import re
import xml.etree.ElementTree as ET
import json

# --- Configuração da Console ---
console = Console()

def extract_version(service_name, details_str):
    version = None
    if not details_str: return None
    alert_index = details_str.upper().find("ALERTA DE SEGURANÇA:")
    info_index = details_str.upper().find("INFO SEGURANÇA:")
    end_of_original_details = len(details_str)
    if alert_index != -1: end_of_original_details = min(end_of_original_details, alert_index)
    if info_index != -1: end_of_original_details = min(end_of_original_details, info_index)
    original_details = details_str[:end_of_original_details].strip()
    service_name_upper = service_name.upper()
    if "FTP" in service_name_upper:
        m = re.search(r"vsFTPd\s+([\w\d\.\-]+)", original_details, re.IGNORECASE)
        if m: version = m.group(1)
    elif "SSH" in service_name_upper:
        m = re.search(r"OpenSSH_([\w\d\.\-p]+)", original_details, re.IGNORECASE)
        if m: version = m.group(1)
    elif "HTTP" in service_name_upper:
        m = re.search(r"Apache/([\d\w\.\-]+)", original_details, re.IGNORECASE)
        if m: version = m.group(1)
    elif "MYSQL" in service_name_upper:
        if re.fullmatch(r"[\w\d\.\-]+(?:-[\w\d\.\-]+)*", original_details) and \
                len(original_details.split('.')) >= 2 and len(original_details) < 30:
            version = original_details
    elif "VNC" in service_name_upper:
        m = re.search(r"RFB\s+([\d\.]+)", original_details, re.IGNORECASE)
        if m: version = m.group(1)
    return version


def parse_banner_scan_report_content(file_content):
    lines = file_content.splitlines()
    parsed_data = []
    current_host_info = None
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("# Varredura de Rede Detalhada para:"): continue
        host_match = re.match(r"Host:\s*(\S+)", line)
        if host_match:
            if current_host_info: parsed_data.append(current_host_info)
            current_host_info = {"host": host_match.group(1), "services": []}
            continue
        if not current_host_info: continue
        no_services_match = re.match(r"Services:\s*(Nenhuma porta aberta.*)", line)
        if no_services_match:
            current_host_info["services"] = no_services_match.group(1).strip()
            continue
        service_line_match = re.match(r"-\s*(\d+)/(tcp|udp):\s*([^:]+?):\s*(.*)", line)
        if service_line_match:
            port = service_line_match.group(1)
            protocol = service_line_match.group(2)
            service_name_from_prefix = service_line_match.group(3).strip()
            full_details_with_recommendations = service_line_match.group(4).strip()
            service_name_match_in_prefix = re.match(r"(\w[\w\s\(\)-]+?)(?:\s*\(Porta \d+\))?$",
                                                    service_name_from_prefix)
            service_name_actual = service_name_match_in_prefix.group(
                1).strip() if service_name_match_in_prefix else service_name_from_prefix
            if service_name_actual.upper() == "MYSQL" and not full_details_with_recommendations:
                if i < len(lines):
                    next_line_content = lines[i].strip()
                    if next_line_content and not next_line_content.startswith("- ") and \
                            not next_line_content.startswith("Host:") and not next_line_content.startswith("Services:"):
                        full_details_with_recommendations = next_line_content
                        i += 1
            version = extract_version(service_name_actual, full_details_with_recommendations)
            service_entry = {"port": port, "protocol": protocol, "service_name": service_name_actual,
                             "details": full_details_with_recommendations}
            if version: service_entry["version"] = version
            if isinstance(current_host_info["services"], str): current_host_info["services"] = []
            current_host_info["services"].append(service_entry)
    if current_host_info: parsed_data.append(current_host_info)
    return parsed_data

def parse_nmap_sv_xml_details(xml_output_sv):
    """
    Parseia a saída XML de um scan Nmap -sV para um ÚNICO host/porta
    e retorna um dicionário com 'product', 'version', 'extrainfo', 'ostype', 'script_outputs'.
    """
    service_details = {}
    script_outputs = {}
    try:
        root = ET.fromstring(xml_output_sv)
        host_node = root.find("host")
        if host_node is None:  # Pode acontecer se o Nmap não encontrar o host (ex: -Pn e host down)
            return {"error": "Host node not found in Nmap XML output."}

        port_node = host_node.find(".//port")  # Encontra o primeiro (e único esperado) nó de porta
        if port_node is not None:
            service_node = port_node.find("service")
            if service_node is not None:
                service_details["nmap_service_name"] = service_node.get("name")
                service_details["product"] = service_node.get("product")
                service_details["version"] = service_node.get("version")
                service_details["extrainfo"] = service_node.get("extrainfo")
                service_details["ostype"] = service_node.get("ostype")

            # Parsear saídas de scripts para esta porta
            for script_node in port_node.findall("script"):
                script_id = script_node.get("id")
                script_output = script_node.get("output")
                if script_id and script_output:
                    script_outputs[script_id] = script_output.strip()
            if script_outputs:
                service_details["script_outputs"] = script_outputs

    except ET.ParseError as e:
        # console.print(f"[yellow][!] Aviso: Falha ao parsear XML do Nmap -sV: {e}[/yellow]")
        service_details["error"] = f"XML Parse Error: {e}"
    return service_details

def run_enhanced_version_detection(structured_initial_data, main_output_file):
    """
    Itera sobre os dados parseados, executa Nmap -sV direcionado para serviços específicos
    e atualiza os dados com informações de versão mais detalhadas.
    Retorna os dados enriquecidos.
    """
    console.print("\n[cyan][*] Iniciando fase de detecção de versão aprimorada para serviços selecionados...[/cyan]")

    # Faz uma cópia profunda para não modificar o original se a referência for usada em outro lugar.
    # No nosso caso atual, modificar in-place é aceitável, mas cópia é mais seguro.
    # enriched_data = json.loads(json.dumps(structured_initial_data)) # Cópia profunda simples
    enriched_data = structured_initial_data  # Modifica in-place

    for host_info in track(enriched_data, description="Aprimorando versões..."):
        host_ip = host_info["host"]
        if not isinstance(host_info["services"], list):  # Caso de "Nenhuma porta aberta..."
            continue

        for service_index, service in enumerate(host_info["services"]):
            port = service["port"]
            protocol = service["protocol"]
            service_name = service.get("service_name", "").upper()
            details = service.get("details", "")
            needs_sv_scan = False
            nmap_sv_scripts = []  # Lista de scripts NSE para rodar com -sV

            # Condição para SMB
            if protocol == "tcp" and (port == "139" or port == "445" or "SMB" in service_name):
                needs_sv_scan = True
                nmap_sv_scripts.extend(["smb-os-discovery", "smb-protocols", "smb-security-mode"])
                console.print(f"[blue][>] Agendando -sV para SMB em {host_ip}:{port}/{protocol}[/blue]",
                              highlight=False)

            # Condição para banners genéricos ou timeouts em TCP onde a versão não foi pega
            # (Evitar re-escanear Telnet, SMTP se já têm recomendação, a menos que queira versão específica)
            elif protocol == "tcp" and not service.get("version"):
                if "GENERIC TCP" in details.upper() or \
                        "TIMEOUT" in details.upper() or \
                        "NO IMMEDIATE BANNER" in details.upper() or \
                        "NO BANNER" in details.upper() and not \
                        (
                                "ALERTA DE SEGURANÇA" in details.upper() or "INFO SEGURANÇA" in details.upper()):  # Não re-escanear se já tem info customizada
                    needs_sv_scan = True
                    console.print(
                        f"[blue][>] Agendando -sV para serviço desconhecido/genérico em {host_ip}:{port}/{protocol}[/blue]",
                        highlight=False)

            if needs_sv_scan:
                if os.geteuid() != 0:  # -sV muitas vezes requer root para algumas sondas
                    console.print(
                        f"[yellow][!] Aviso: -sV para {host_ip}:{port} pode ser limitado sem permissões de root.[/yellow]")

                nmap_command = ["nmap", "-sV", "-Pn"]  # -Pn para não pular hosts se ping falhar nesta fase
                if os.geteuid() == 0:  # Adiciona sudo se não for root, mas o script principal já checa root
                    nmap_command.insert(0, "sudo")

                nmap_command.extend(["-p", f"T:{port}"])  # Especifica TCP e a porta
                if nmap_sv_scripts:
                    nmap_command.append("--script")
                    nmap_command.append(",".join(nmap_sv_scripts))
                nmap_command.extend([host_ip, "-oX", "-"])

                console.print(f"  Executando: {' '.join(nmap_command)}", highlight=False)
                try:
                    sv_result = subprocess.run(nmap_command, capture_output=True, text=True, check=False,
                                               timeout=180)  # Timeout de 3 min
                    if sv_result.returncode == 0 and sv_result.stdout:
                        sv_details = parse_nmap_sv_xml_details(sv_result.stdout)
                        if sv_details and not sv_details.get("error"):
                            service["nmap_sv_info"] = sv_details  # Adiciona os novos detalhes

                            # Tenta atualizar o campo 'version' e 'details' principal se novas infos foram encontradas
                            new_product = sv_details.get("product")
                            new_version = sv_details.get("version")
                            new_extrainfo = sv_details.get("extrainfo")

                            updated_details_parts = []
                            if new_product: updated_details_parts.append(new_product)
                            if new_version:
                                updated_details_parts.append(f"(Versão: {new_version})")
                                service["version"] = new_version  # Atualiza a versão principal
                            if new_extrainfo: updated_details_parts.append(f"({new_extrainfo})")

                            if updated_details_parts:
                                service[
                                    "details"] = f"{service['details']}. INFO NMAP -sV: {' '.join(updated_details_parts)}"

                            console.print(
                                f"  [green]Informação de versão aprimorada para {host_ip}:{port} obtida.[/green]",
                                highlight=False)
                        elif sv_details.get("error"):
                            console.print(
                                f"  [yellow]Erro ao parsear -sV XML para {host_ip}:{port}: {sv_details.get('error')}[/yellow]",
                                highlight=False)
                            service["nmap_sv_info"] = {"error": f"Nmap -sV parsing error: {sv_details.get('error')}"}
                        else:
                            service["nmap_sv_info"] = {"status": "Nenhuma informação de serviço detalhada do -sV."}
                    elif sv_result.stderr:
                        console.print(
                            f"  [yellow]Nmap -sV para {host_ip}:{port} retornou erro: {sv_result.stderr.strip()[:100]}[/yellow]",
                            highlight=False)
                        service["nmap_sv_info"] = {
                            "error": f"Nmap -sV execution error: {sv_result.stderr.strip()[:100]}"}
                except subprocess.TimeoutExpired:
                    console.print(f"  [red]Nmap -sV para {host_ip}:{port} deu timeout.[/red]", highlight=False)
                    service["nmap_sv_info"] = {"error": "Nmap -sV command timed out"}
                except Exception as e:
                    console.print(f"  [red]Falha ao executar Nmap -sV para {host_ip}:{port}: {e}[/red]",
                                  highlight=False)
                    service["nmap_sv_info"] = {"error": f"Exception during Nmap -sV: {str(e)}"}

                time.sleep(0.5)  # Pequena pausa para não sobrecarregar

    console.print("[green][+] Fase de detecção de versão aprimorada concluída.[/green]")
    return enriched_data


# --- Funções de Banner Grabbing, Handlers, Validação, etc. ---
def _grab_banner_generic_tcp(sock, host, port):
    sock.settimeout(2)
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if banner:
        return f"Generic TCP: {banner[:60]}"
    return "Generic TCP: No immediate banner"

def _grab_ftp_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    return f"FTP: {banner[:60]}" if banner else "FTP: No banner"

def _grab_ssh_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    return f"SSH: {banner[:60]}" if banner else "SSH: No banner"


def _grab_telnet_banner(sock, host, port):  # TCP
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if banner and not banner.upper().startswith("TELNET:"):
        return f"Telnet: {banner[:60]}"
    elif not banner:
        return "Telnet: No banner"
    return banner[:70]

def _grab_smtp_banner(sock, host, port):  # TCP
    try:
        sock.settimeout(2)
        initial_banner_bytes = sock.recv(1024)
        initial_banner = initial_banner_bytes.decode('utf-8', errors='ignore').strip()
        sock.settimeout(3)
        final_banner_str = initial_banner
        if "220" in initial_banner:
            try:
                sock.sendall(b"EHLO example.com\r\n")
                ehlo_banner_bytes = sock.recv(1024)
                ehlo_banner = ehlo_banner_bytes.decode('utf-8', errors='ignore').strip()
                if ehlo_banner:
                    first_initial = initial_banner.splitlines()[0] if initial_banner.splitlines() else initial_banner
                    first_ehlo = ehlo_banner.splitlines()[0] if ehlo_banner.splitlines() else ehlo_banner
                    final_banner_str = f"{first_initial}; {first_ehlo}"
            except socket.timeout:
                pass
            except Exception:
                pass
        if not final_banner_str: return "SMTP: No banner"
        if not final_banner_str.upper().startswith("SMTP:"):
            return f"SMTP: {final_banner_str[:60]}"
        return final_banner_str[:70]
    except socket.timeout:
        return "SMTP: Timeout"
    except Exception as e:
        return f"SMTP: Error ({str(e)[:45]})"

def _grab_http_banner_logic(sock, host, port_num, service_name="HTTP"):
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: IT-Scanner\r\nConnection: close\r\n\r\n"
    sock.send(request.encode('utf-8'))
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    for line in banner.splitlines():
        if line.lower().startswith('server:'):
            return f"{service_name}: {line.split(':', 1)[1].strip()[:60]}"
    return f"{service_name}: No server banner"

def _grab_http_banner(sock, host, port): return _grab_http_banner_logic(sock, host, port, "HTTP")


def _grab_http_alt_banner(sock, host, port): return _grab_http_banner_logic(sock, host, port, "HTTP (Alt)")

def _grab_pop3_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if not banner.upper().startswith("POP3:"):
        return f"POP3: {banner[:60]}" if banner else "POP3: No banner"
    return banner[:70]

def _grab_rpc_banner(sock, host, port): return "RPC: Service detected"

def _grab_imap_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if not banner.upper().startswith("IMAP:"):
        return f"IMAP: {banner[:60]}" if banner else "IMAP: No banner"
    return banner[:70]

def _grab_https_banner(sock, host, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False;
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False) as ssock:
            ssock.do_handshake()
            cert = ssock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject.get('commonName', 'N/A')
                return f"HTTPS: CommonName={common_name[:55]}"
            else:
                return "HTTPS: Connection successful, no peer certificate"
    except ssl.SSLError as ssl_e:
        return f"HTTPS: TLS Error ({str(ssl_e)[:55]})"
    except Exception as e:
        return f"HTTPS: Connection or Handshake Error ({str(e)[:40]})"

def _grab_smb_banner(sock, host, port):
    smb_packet = bytes.fromhex("0000002fff534d42720000000000000000000000000000000000000000000000")
    try:
        sock.send(smb_packet)
        banner = sock.recv(1024).hex()
        return f"SMB: Negotiated (hex: {banner[:55]})" if banner else "SMB: No response"
    except Exception as e:
        return f"SMB: Error ({str(e)[:45]})"

def _grab_mssql_banner(sock, host, port):
    banner = sock.recv(1024).hex()
    return f"MSSQL: Detected (hex: {banner[:55]})" if banner else "MSSQL: No response"

def _grab_mysql_banner(sock, host, port):
    banner_content = sock.recv(1024)
    try:
        if len(banner_content) > 5:
            null_byte_index = banner_content.find(b'\x00', 5)
            if null_byte_index != -1:
                version_info = banner_content[5:null_byte_index].decode('utf-8', errors='ignore')
                return f"MySQL: {version_info[:60]}"
        return f"MySQL: Detected (hex: {banner_content.hex()[:55]})" if banner_content else "MySQL: No banner"
    except Exception:
        return f"MySQL: Detected (raw hex: {banner_content.hex()[:50]})" if banner_content else "MySQL: No banner"


def _grab_rdp_banner(sock, host, port): return "RDP: Service detected"

def _grab_postgresql_banner(sock, host, port):
    try:
        banner_bytes = sock.recv(1024)
        if banner_bytes:
            try:
                banner_text = banner_bytes.decode('utf-8', errors='replace').strip()
                if banner_text and (
                        banner_text.startswith('E') or banner_text.startswith('R') or banner_text.startswith('N')):
                    return f"PostgreSQL: Initial response detected ('{banner_text[0]}')"
                if banner_text: return f"PostgreSQL: Response (text: {banner_text[:50]})"
                return f"PostgreSQL: Response (hex: {banner_bytes.hex()[:50]})"
            except UnicodeDecodeError:
                return f"PostgreSQL: Response (hex: {banner_bytes.hex()[:50]})"
        return "PostgreSQL: No immediate banner"
    except Exception:
        return "PostgreSQL: No immediate banner / Timeout"


def _grab_vnc_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if banner.startswith("RFB"): return f"VNC: {banner[:60]}"
    return f"VNC: Detected (banner: {banner[:55]})" if banner else "VNC: No banner"


def _grab_redis_banner(sock, host, port):
    sock.sendall(b"INFO\r\n")
    banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
    if banner.startswith("$") or banner.startswith("#"):
        first_line = banner.splitlines()[0] if banner.splitlines() else ""
        return f"Redis: INFO Response ({first_line[:55]})"
    return f"Redis: {banner[:60]}" if banner else "Redis: No banner"


TCP_BANNER_HANDLERS = {
    21: _grab_ftp_banner, 22: _grab_ssh_banner, 23: _grab_telnet_banner, 25: _grab_smtp_banner,
    80: _grab_http_banner, 110: _grab_pop3_banner, 135: _grab_rpc_banner, 143: _grab_imap_banner,
    443: _grab_https_banner, 445: _grab_smb_banner, 1433: _grab_mssql_banner, 3306: _grab_mysql_banner,
    3389: _grab_rdp_banner, 5432: _grab_postgresql_banner, 5900: _grab_vnc_banner,
    6379: _grab_redis_banner, 8080: _grab_http_alt_banner,
}


def _grab_banner_generic_udp(sock, host, port):
    try:
        sock.sendto(b"\x00", (host, port))
        banner, _ = sock.recvfrom(1024)
        return f"Generic UDP: Response (hex: {banner.hex()[:50]})" if banner else "Generic UDP: No response to null byte"
    except socket.timeout:
        return "Generic UDP: Timeout on null byte probe"
    except Exception:
        return "Generic UDP: Service detected (no specific banner probe)"


def _grab_dns_banner_udp(sock, host, port):
    dns_packet = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    sock.sendto(dns_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    if banner and banner[:2] == dns_packet[:2]: return f"DNS: Valid response (hex: {banner.hex()[:50]})"
    return f"DNS: Response (hex: {banner.hex()[:50]})" if banner else "DNS: No response"


def _grab_dhcp_server_banner_udp(sock, host, port): return "DHCP Server: Detected (standard port)"

def _grab_dhcp_client_banner_udp(sock, host, port): return "DHCP Client: Detected (standard port)"

def _grab_tftp_banner_udp(sock, host, port):
    tftp_packet = b"\x00\x01" + b"testfile" + b"\x00" + b"octet" + b"\x00"
    sock.sendto(tftp_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    if banner and banner[:2] == b"\x00\x05":
        error_code = int.from_bytes(banner[2:4], 'big')
        return f"TFTP: Error packet (code {error_code}) (hex: {banner.hex()[:45]})"
    return f"TFTP: Response (hex: {banner.hex()[:50]})" if banner else "TFTP: No response"

def _grab_ntp_banner_udp(sock, host, port):
    ntp_packet = bytearray(48);
    ntp_packet[0] = 0b00100011
    sock.sendto(ntp_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    if banner and len(banner) == 48: return f"NTP: Valid response (hex: {banner.hex()[:50]})"
    return f"NTP: Response (hex: {banner.hex()[:50]})" if banner else "NTP: No response"

def _grab_netbios_ns_banner_udp(sock, host, port):
    nbns_query = bytes.fromhex(
        "00000010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001")
    sock.sendto(nbns_query, (host, port))
    banner, _ = sock.recvfrom(1024)
    return f"NetBIOS Name: Response (hex: {banner.hex()[:45]})" if banner else "NetBIOS Name: No response"

def _grab_netbios_dgm_banner_udp(sock, host, port): return "NetBIOS Datagram: Detected (standard port)"

def _grab_snmp_banner_udp(sock, host, port):
    snmp_packet = bytes.fromhex("302602010104067075626c6963a019020400000000020100020100300b300906052b0601020101010500")
    sock.sendto(snmp_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    try:
        if banner and banner[0] == 0x30: return f"SNMP: Response (hex: {banner.hex()[:50]})"
        decoded_banner = banner.decode('utf-8', errors='ignore').strip()
        return f"SNMP: {decoded_banner[:50]}" if decoded_banner else f"SNMP: Response (hex: {banner.hex()[:50]})"
    except Exception:
        return f"SNMP: Response (hex: {banner.hex()[:50]})" if banner else "SNMP: No response"

def _grab_snmp_trap_banner_udp(sock, host, port): return "SNMP Trap: Detected (standard port)"

def _grab_isakmp_banner_udp(sock, host, port):
    ike_packet = os.urandom(8) + b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x2c" + \
                 b"\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01"
    sock.sendto(ike_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    return f"ISAKMP/IKE: Response (hex: {banner.hex()[:50]})" if banner else "ISAKMP/IKE: No response"

def _grab_syslog_banner_udp(sock, host, port): return "Syslog: Detected (standard port, typically no banner)"

def _grab_ipsec_natt_banner_udp(sock, host, port):
    natt_keepalive = b"\x00\x00\x00\x00\xff"
    sock.sendto(natt_keepalive, (host, port))
    try:
        banner, _ = sock.recvfrom(1024)
        return f"IPSec NAT-T: Response (hex: {banner.hex()[:45]})" if banner else "IPSec NAT-T: No direct response"
    except socket.timeout:
        return "IPSec NAT-T: Detected (no response to keepalive)"

UDP_BANNER_HANDLERS = {
    53: _grab_dns_banner_udp, 67: _grab_dhcp_server_banner_udp, 68: _grab_dhcp_client_banner_udp,
    69: _grab_tftp_banner_udp, 123: _grab_ntp_banner_udp, 137: _grab_netbios_ns_banner_udp,
    138: _grab_netbios_dgm_banner_udp, 161: _grab_snmp_banner_udp, 162: _grab_snmp_trap_banner_udp,
    500: _grab_isakmp_banner_udp, 514: _grab_syslog_banner_udp, 4500: _grab_ipsec_natt_banner_udp,
}


def validate_input(target):
    try:
        ipaddress.ip_network(target, strict=False); return "network"
    except ValueError:
        pass
    try:
        ipaddress.ip_address(target); return "host"
    except ValueError:
        pass
    try:
        socket.gethostbyname(target); return "url"
    except socket.gaierror:
        console.print(f"[red][!] Erro: Alvo '{target}' inválido.[/red]")
        return None


def check_nmap_installed():
    try:
        subprocess.run(["nmap", "-V"], capture_output=True, check=True, text=True); return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def grab_banner_tcp(host, port, timeout=3):
    banner_function = TCP_BANNER_HANDLERS.get(port, _grab_banner_generic_tcp)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout);
        sock.connect((host, port))
        return banner_function(sock, host, port)
    except socket.timeout:
        return "Timeout"
    except ConnectionRefusedError:
        return "Connection Refused"
    except Exception as e:
        return f"Error: {str(e)[:60]}"
    finally:
        if sock: sock.close()


def grab_banner_udp(host, port, timeout=3):
    banner_function = UDP_BANNER_HANDLERS.get(port, _grab_banner_generic_udp)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        return banner_function(sock, host, port)
    except socket.timeout:
        return "Timeout"
    except ConnectionRefusedError:
        return "Connection Refused (ICMP)"
    except Exception as e:
        return f"Error: {str(e)[:60]}"
    finally:
        if sock: sock.close()


def parse_nmap_xml_output(xml_output):  # Para scans de porta
    open_ports = []
    try:
        root = ET.fromstring(xml_output)
        for host_element in root.findall('host'):
            status_element = host_element.find('status')
            if status_element is None or status_element.get('state') != 'up': continue
            ports_element = host_element.find('ports')
            if ports_element is not None:
                for port_element in ports_element.findall('port'):
                    state_element = port_element.find('state')
                    if state_element is not None and state_element.get('state') == 'open':
                        open_ports.append((port_element.get('portid'), port_element.get('protocol')))
    except ET.ParseError as e:
        console.print(f"[yellow][!] Aviso: Parse XML (portas): {e}[/yellow]")
    return open_ports


def discover_hosts(target, input_type, output_file="scan_results.txt"):  # Nome do arquivo de output do scan de banner
    active_hosts_ips = []
    start_time = time.time()
    try:
        if not check_nmap_installed():
            console.print("[red][!] Erro: Nmap não está instalado.[/red]");
            return []
        if os.geteuid() != 0 and not ('--no-root-check' in sys.argv or os.environ.get(
                "ALLOW_NO_ROOT") == "1"):  # Adicionada verificação para permitir rodar sem root para testes limitados
            console.print(
                "[red][!] Aviso: Algumas funcionalidades (ex: Nmap -sS) requerem root. Rodando em modo limitado.[/red]")
            # Não retorna [], permite continuar com scans que não exigem root, como -sT ou -sn sem certas opções
        if not input_type: return []

        console.print(f"[cyan][*] Iniciando descoberta em {target} ({input_type})...[/cyan]")
        command_list = ["nmap", "-sn", "-T4", target, "-oG", "-"]
        result = subprocess.run(command_list, capture_output=True, text=True, check=False)
        if result.returncode != 0 and result.stderr: console.print(
            f"[yellow][!] Nmap (descoberta): {result.stderr.strip()}[/yellow]")
        if result.stdout:
            for line in result.stdout.splitlines():
                if "Status: Up" in line:
                    match = re.search(r"Host:\s*([0-9a-fA-F.:]+)", line)
                    if match: active_hosts_ips.append(match.group(1))
        if not active_hosts_ips:
            if input_type != "network":
                try:
                    resolved_ip = socket.gethostbyname(target)
                    console.print(
                        f"[yellow][!] Ping scan falhou para '{target}', tentando IP resolvido: {resolved_ip}[/yellow]")
                    active_hosts_ips = [resolved_ip]
                except socket.gaierror:
                    console.print(f"[red][!] Não foi possível resolver IP para '{target}'.[/red]");
                    return []
            else:
                console.print(f"[yellow][!] Nenhum host ativo encontrado em {target}.[/yellow]");
                return []
        console.print(f"[green][+] Hosts ativos preliminares: {active_hosts_ips}[/green]")

        common_tcp_ports = "21,22,23,25,80,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080"
        # Para UDP, -F (Fast scan) no Nmap é geralmente mais eficiente do que uma lista longa para scans iniciais.
        # common_udp_ports = "53,67,68,69,123,137,138,161,162,500,514,4500"

        console.print("[cyan][*] Enumerando portas e coletando banners...[/cyan]")
        host_details_for_report = []

        with open(output_file, "w", encoding="utf-8") as f_report:
            f_report.write(f"# Varredura de Rede Detalhada para: {target} em {time.ctime(start_time)}\n")

        nmap_scan_type = "-sS" if os.geteuid() == 0 else "-sT"  # Usa SYN scan se root, senão TCP Connect

        for host in track(active_hosts_ips, description="Varrendo hosts e banners"):
            current_host_banner_infos = []
            open_ports_nmap = []

            tcp_cmd = ["nmap", nmap_scan_type, "-T4", "--max-retries", "1", "--host-timeout", "3m", "-p",
                       common_tcp_ports, host, "-oX", "-"]
            tcp_res = subprocess.run(tcp_cmd, capture_output=True, text=True, check=False)
            if tcp_res.stderr and "Failed to resolve" not in tcp_res.stderr:
                console.print(f"[yellow][!] Nmap TCP ({host}): {tcp_res.stderr.strip()[:100]}[/yellow]",
                              highlight=False)
            open_ports_nmap.extend(parse_nmap_xml_output(tcp_res.stdout))

            # UDP scan é demorado, usando -F para as portas mais comuns e rápidas
            udp_cmd = ["nmap", "-sU", "-T4", "--max-retries", "0", "--host-timeout", "5m", "-F", "--max-scan-delay",
                       "20ms", host, "-oX", "-"]
            udp_res = subprocess.run(udp_cmd, capture_output=True, text=True, check=False)
            if udp_res.stderr and "Failed to resolve" not in udp_res.stderr:
                console.print(f"[yellow][!] Nmap UDP ({host}): {udp_res.stderr.strip()[:100]}[/yellow]",
                              highlight=False)
            open_ports_nmap.extend(parse_nmap_xml_output(udp_res.stdout))

            unique_open_ports = sorted(list(set(open_ports_nmap)), key=lambda x: (int(x[0]), x[1]))

            for port_str, proto in unique_open_ports:
                port_int = int(port_str)
                raw_banner_or_status = ""
                if proto == "tcp":
                    raw_banner_or_status = grab_banner_tcp(host, port_int)
                elif proto == "udp":
                    raw_banner_or_status = grab_banner_udp(host, port_int)

                current_banner_info = raw_banner_or_status if raw_banner_or_status and raw_banner_or_status not in [
                    "Timeout", "Connection Refused",
                    "Connection Refused (ICMP)"] else f"{raw_banner_or_status if raw_banner_or_status else 'Nenhuma resposta específica do banner grabber'}"
                original_banner_part = current_banner_info  # Para extração de versão antes de adicionar recomendações

                if port_int == 23 and proto == "tcp":
                    recommendation = "ALERTA DE SEGURANÇA: Telnet é inseguro. Por favor, desabilite e substitua pelo SSH (Secure Shell) que é criptografado."
                    if not current_banner_info.upper().startswith("TELNET:"):
                        current_banner_info = f"Telnet (Porta 23): {current_banner_info}. {recommendation}"
                    else:
                        current_banner_info = f"{current_banner_info}. {recommendation}"
                elif (port_int == 445 or port_int == 139) and proto == "tcp":
                    recommendation = (
                        "INFO SEGURANÇA (SMB): Recomenda-se análise com Nmap -sV e scripts (ex: smb-os-discovery, smb-protocols, smb-vuln-*) "
                        "e enum4linux-ng para verificar compartilhamentos, configurações (SMBv1?) e CVEs (ex: MS17-010).")
                    service_prefix = f"SMB (Porta {port_int})"
                    if not current_banner_info.upper().startswith("SMB:"):
                        current_banner_info = f"{service_prefix}: {current_banner_info}. {recommendation}"
                    else:
                        current_banner_info = f"{current_banner_info}. {recommendation}"
                elif (port_int == 25 or port_int == 587 or port_int == 465) and proto == "tcp":
                    recommendation = (
                        "INFO SEGURANÇA (SMTP): Verifique se o servidor não é um open relay. Mantenha o software atualizado. "
                        "Implemente SPF, DKIM e DMARC para segurança de e-mail.")
                    service_prefix = f"SMTP (Porta {port_int})"
                    if not current_banner_info.upper().startswith("SMTP:"):
                        current_banner_info = f"{service_prefix}: {current_banner_info}. {recommendation}"
                    else:
                        current_banner_info = f"{current_banner_info}. {recommendation}"

                if raw_banner_or_status or "ALERTA DE SEGURANÇA" in current_banner_info or "INFO SEGURANÇA" in current_banner_info:
                    current_host_banner_infos.append(f"{port_str}/{proto}: {current_banner_info}")

            if not current_host_banner_infos:
                current_host_banner_infos.append(
                    "Nenhuma porta aberta com banner detectada ou Nmap falhou em obter portas.")
            host_details_for_report.append({"host": host, "ports_info": current_host_banner_infos})

            with open(output_file, "a", encoding="utf-8") as f_report:
                f_report.write(f"\nHost: {host}\n")
                if current_host_banner_infos == [
                    "Nenhuma porta aberta com banner detectada ou Nmap falhou em obter portas."]:
                    f_report.write(f"  Services: {current_host_banner_infos[0]}\n")
                else:
                    for port_info_line in current_host_banner_infos:
                        f_report.write(f"  - {port_info_line}\n")

        table = Table(title=f"Hosts Ativos e Serviços ({target})", show_lines=True,
                      width=console.width if console.width > 100 else 100)
        table.add_column("IP", style="cyan", width=16, overflow="fold")
        table.add_column("Porta/Proto", style="magenta", width=15, overflow="fold")
        table.add_column("Serviço (Banner/Status/Info)", style="green", overflow="fold")  # Largura dinâmica

        if not host_details_for_report: console.print(f"[yellow][!] Nenhum detalhe de host/porta para exibir.[/yellow]")
        for detail_entry in host_details_for_report:
            host_ip = detail_entry["host"]
            ports_info_list = detail_entry["ports_info"]
            if ports_info_list == ["Nenhuma porta aberta com banner detectada ou Nmap falhou em obter portas."]:
                table.add_row(host_ip, "-", ports_info_list[0])
            else:
                first_port_for_this_host = True
                for port_info_line in ports_info_list:
                    parts = port_info_line.split(": ", 1)
                    port_proto_display = parts[0]
                    banner_text_display = parts[1] if len(parts) > 1 else "N/A"
                    if first_port_for_this_host:
                        table.add_row(host_ip, port_proto_display, banner_text_display)
                        first_port_for_this_host = False
                    else:
                        table.add_row("", port_proto_display, banner_text_display)
        console.print(table)
        end_time = time.time()
        console.print(f"[green][+] Varredura concluída em {end_time - start_time:.2f} segundos.[/green]")
        console.print(f"[green][+] Total de hosts ativos processados: {len(active_hosts_ips)}[/green]")
        console.print(f"[green][+] Resultados detalhados salvos em: {output_file}[/green]")
        return active_hosts_ips
    except KeyboardInterrupt:
        console.print("[yellow][!] Varredura interrompida.[/yellow]"); return []
    except Exception as e:
        console.print(f"[red][!] Erro inesperado no discover_hosts: {e}[/red]")
        import traceback;
        traceback.print_exc();
        return []


def main():
    parser = argparse.ArgumentParser(description="Scanner de hosts com Nmap e banner grabbing.")
    parser.add_argument("-t", "--target", type=str, help="Alvo (ex.: 192.168.1.0/24, 192.168.1.1, server.local)")
    parser.add_argument("-o", "--output", type=str, default="scan_results.txt",
                        help="Arquivo de saída do scan (padrão: scan_results.txt)")
    parser.add_argument("-jo", "--json-output", type=str, help="Arquivo JSON para dados parseados (opcional).")
    parser.add_argument("--no-root-check", action="store_true",
                        help="Permitir execução sem root (funcionalidade limitada).")  # Novo argumento
    # parser.add_argument("-v", "--verbose", action="store_true", help="Logs detalhados (sem efeito extra atualmente).") # Verbose não implementado
    args = parser.parse_args()

    if args.no_root_check:
        os.environ["ALLOW_NO_ROOT"] = "1"  # Sinaliza para discover_hosts

    target = args.target
    if not target:
        console.print("[cyan][*] Digite o alvo (ex.: 192.168.1.0/24): [/cyan]", end="")
        try:
            target = input().strip()
        except KeyboardInterrupt:
            console.print("\n[yellow][!] Entrada cancelada.[/yellow]"); sys.exit(0)
    if not target: console.print("[red][!] Nenhum alvo fornecido.[/red]"); sys.exit(1)
    input_type = validate_input(target)
    if not input_type: sys.exit(1)

    active_hosts_scanned = discover_hosts(target, input_type, output_file=args.output)

    # Fase de Parseamento e Análise Aprimorada (Nmap -sV)
    if os.path.exists(args.output):
        if active_hosts_scanned: console.print(f"[green][+] Hosts escaneados: {active_hosts_scanned}[/green]")

        console.print(f"\n[cyan][*] Parseando '{args.output}' para JSON...[/cyan]")
        try:
            with open(args.output, "r", encoding="utf-8") as f:
                report_content = f.read()
            report_lines = report_content.strip().splitlines()
            if not report_content.strip() or (
                    len(report_lines) <= 1 and report_lines[0].startswith("# Varredura de Rede Detalhada para:")):
                console.print(
                    f"[yellow][!] Relatório '{args.output}' vazio ou apenas com cabeçalho. Sem dados para JSON.[/yellow]")
            else:
                structured_data = parse_banner_scan_report_content(report_content)

                # --- CHAMADA PARA DETECÇÃO DE VERSÃO APRIMORADA ---
                # Esta função irá modificar 'structured_data' in-place
                run_enhanced_version_detection(structured_data, os.path.splitext(args.output)[0])
                # --- FIM DA CHAMADA ---

                json_file_name = args.json_output if args.json_output else f"{os.path.splitext(args.output)[0]}_enriched.json"  # Alterado nome para _enriched
                with open(json_file_name, "w", encoding="utf-8") as json_f:
                    json.dump(structured_data, json_f, indent=2, ensure_ascii=False)
                console.print(f"\n[green][+] Dados parseados e enriquecidos salvos em: '{json_file_name}'[/green]")
        except FileNotFoundError:
            console.print(f"[red][!] Relatório '{args.output}' não encontrado para parsear.[/red]")
        except Exception as e:
            console.print(f"[red][!] Erro ao parsear/enriquecer relatório '{args.output}': {e}[/red]")
            console.print_exception(show_locals=True)
    else:
        console.print(f"[yellow][!] Relatório '{args.output}' não gerado.[/yellow]")
        if not active_hosts_scanned: console.print("[yellow][!] Nenhum host ativo encontrado.[/yellow]")


if __name__ == "__main__":
    main()
