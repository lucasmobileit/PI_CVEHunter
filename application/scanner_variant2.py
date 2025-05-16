#!/usr/bin/env python3
"""
Fast asset/port scanner + banner‑grabber (TI / IoT / OT ready) – score 8/10
• zero tmp files • type‑safe • concurrent • minimal external deps (nmap + rich + requests)
• Alinhado ao NIST 800-53 RA-5: escaneamento de vulnerabilidades, correlação com CVEs, 
  enriquecimento com CVSS scores e relatórios estruturados.
"""

from __future__ import annotations
import argparse, ipaddress, os, socket, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from shutil import which
from typing import List, Tuple, Dict

import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.table import Table

console = Console()

# ---------- helpers -----------------------------------------------------------

def require_root() -> None:
    if os.geteuid():
        console.print("[red]Execute como root.[/red]"); sys.exit(1)

def require_nmap() -> None:
    if not which("nmap"):
        console.print("[red]Instale nmap.[/red]"); sys.exit(1)

def classify(target: str) -> str:
    try:
        ipaddress.ip_network(target, strict=False);      return "network"
    except ValueError:
        pass
    try:
        ipaddress.ip_address(target);                    return "host"
    except ValueError:
        pass
    try:
        socket.gethostbyname(target);                    return "url"
    except socket.gaierror:
        console.print(f"[red]Alvo inválido: {target}[/red]"); sys.exit(1)

def run(cmd: List[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode: console.print(res.stderr, style="red"); sys.exit(res.returncode)
    return res.stdout

# ---------- scanning ----------------------------------------------------------

TCP_PORTS = [21,22,23,25,80,443,445,502,1883,3306]
UDP_PORTS = [53,47808]

def nmap_discover(target: str, kind: str) -> list[str]:
    """Para redes faz ping‑sweep; para host/url pula discovery (RA-5: identificação de ativos)."""
    if kind == "network":
        out = run(["nmap", "-sn", target, "-oG", "-"])
        return [l.split()[1] for l in out.splitlines() if "Status: Up" in l]
    return [target]

def nmap_ports(host: str) -> list[tuple[int, str]]:
    """Enumera portas pré‑definidas usando -Pn (RA-5: escaneamento automatizado)."""
    tcp = run([
        "nmap", "-Pn", "-sS",
        "-p", ",".join(map(str, TCP_PORTS)),
        "--min-rate", "500", host, "-oG", "-"
    ])
    udp = run([
        "nmap", "-Pn", "-sU",
        "-p", ",".join(map(str, UDP_PORTS)),
        "--min-rate", "1000", host, "-oG", "-"
    ])

    open_ports: list[tuple[int, str]] = []
    for line in (tcp + udp).splitlines():
        if "Ports:" not in line:
            continue
        for item in line.split("Ports:")[1].split(","):
            if "/open/" not in item:
                continue
            parts = item.split("/")
            if len(parts) >= 3:
                port, proto = parts[0], parts[2]
                open_ports.append((int(port), proto))
    return open_ports

# ---------- banner grabbing ---------------------------------------------------

def banner_tcp(host: str, port: int, timeout: int = 3) -> str:
    try:
        with socket.create_connection((host, port), timeout) as s:
            s.settimeout(timeout)
            
            if port == 3306:  # MySQL
                s.sendall(b"\x0a\x00\x00\x01\x85\xa6\x0f\x00\x00\x00\x01")
                time.sleep(0.5)
                response = s.recv(1024).decode(errors="ignore").strip()
                return response if response else "MySQL: sem banner claro"
            
            elif port == 23:  # Telnet
                s.sendall(b"\n")
                time.sleep(0.5)
                response = s.recv(1024).decode(errors="ignore").strip()
                return response if response else "Telnet: sem banner claro"
            
            elif port == 445:  # SMB
                s.sendall(bytes.fromhex("0000002fff534d42420000000000000000000000000000000000000000000000"))
                time.sleep(1.5)
                response = s.recv(1024)
                try:
                    decoded = response.decode(errors="ignore").strip()
                    return decoded if decoded else response.hex()[:50]
                except:
                    return response.hex()[:50]
            
            elif port in (80, 443):  # HTTP/HTTPS
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                response = s.recv(1024).decode(errors="ignore").strip()
                for line in response.splitlines():
                    if line.lower().startswith("server:"):
                        return line[:50]
                return response[:50] if response else "HTTP: sem banner claro"
            
            elif port == 22:  # SSH
                time.sleep(0.5)
                response = s.recv(1024).decode(errors="ignore").strip()
                return response if response else "SSH: sem banner claro"
            
            elif port == 25:  # SMTP
                s.sendall(b"EHLO test\r\n")
                time.sleep(0.5)
                response = s.recv(1024).decode(errors="ignore").strip()
                return response if response else "SMTP: sem banner claro"
            
            else:  # Caso genérico
                time.sleep(0.5)
                response = s.recv(1024).decode(errors="ignore").strip()
                return response[:50] if response else "Sem banner claro"

    except socket.timeout:
        return f"Erro: timeout após {timeout}s"
    except ConnectionRefusedError:
        return "Erro: conexão recusada"
    except Exception as e:
        return f"Erro: {str(e)}"

def banner_udp(host: str, port: int, timeout: int = 3) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            if port == 53:  # DNS
                s.sendto(bytes.fromhex("000001000001000000000000036e733103636f6d0000010001"), (host, port))
            elif port == 47808:  # BACnet
                s.sendto(bytes.fromhex("810b000801002004fffe"), (host, port))
            data, _ = s.recvfrom(120)
            return data.hex()[:40]
    except Exception as e:
        return f"err:{e}"

# ---------- vulnerability correlation (RA-5 compliance) -----------------------

def get_cvss_severity(score: float) -> str:
    """Mapeia pontuação CVSS para severidade (RA-5: priorização de vulnerabilidades)."""
    if score == 0.0:
        return "Nenhuma"
    elif score <= 3.9:
        return "Baixa"
    elif score <= 6.9:
        return "Média"
    elif score <= 8.9:
        return "Alta"
    else:
        return "Crítica"

# Cache para evitar chamadas repetidas à API para o mesmo serviço/versão
vuln_cache: Dict[str, List[Tuple[str, float, str]]] = {}

def check_vulnerabilities(host: str, port: int, proto: str, banner: str) -> List[Tuple[str, float, str]]:
    """
    Consulta a API do VulnCheck para CVEs e CVSS scores (RA-5: correlação com bases de vulnerabilidades).
    Retorna lista de tuplas (CVE, CVSS score, severidade).
    """
    api_token = "vulncheck_075d3ae340106515866559aa4a403eb1668c282a56fcdf16108a1b575d648459"  # Substitua pelo seu token da API do VulnCheck
    if not api_token or api_token == "vulncheck_075d3ae340106515866559aa4a403eb1668c282a56fcdf16108a1b575d648459":
        console.print("[red]Erro: Token de API do VulnCheck não configurado. Gere um token em https://vulncheck.com/.[/red]")
        return [("Token de API não configurado", 0.0, "Nenhuma")]

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {api_token}"
    }
    url = "https://api.vulncheck.com/v3/backup/vulncheck-kev"

    # Extrai o nome do serviço e versão do banner
    service = ""
    version = ""
    if "vsFTPd" in banner:
        service = "vsftpd"
        version = banner.split("vsFTPd ")[1].split(")")[0]
    elif "OpenSSH" in banner:
        service = "openssh"
        version = banner.split("OpenSSH_")[1].split(" ")[0]
    elif "Apache" in banner:
        service = "apache"
        version = banner.split("Apache/")[1].split(" ")[0]
    elif "MySQL" in banner:
        service = "mysql"
        version = banner.split("MySQL ")[1] if "MySQL " in banner else ""
    elif "Postfix" in banner:
        service = "postfix"
        version = banner.split("Postfix ")[1].split(" ")[0] if "Postfix " in banner else ""

    if not service:
        return [("Nenhuma CVE detectada", 0.0, "Nenhuma")]

    # Verifica cache
    cache_key = f"{service}:{version}"
    if cache_key in vuln_cache:
        return vuln_cache[cache_key]

    # Monta a query CPE
    query_params = {
        "query": f"cpe:2.3:a:{service}:{service}:{version}:*:*:*:*:*:*"
    }

    try:
        response = requests.get(url, headers=headers, params=query_params, timeout=5)
        response.raise_for_status()
        data = response.json()

        # Extrai CVEs e CVSS scores
        results = []
        for item in data.get("data", []):
            cve_id = item.get("id", "")
            if not cve_id.startswith("CVE"):
                continue
            cvss_score = 0.0
            # Busca CVSS v3.1 ou v2
            metrics = item.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss_score = float(metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0))
            elif "cvssMetricV2" in metrics:
                cvss_score = float(metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0))
            severity = get_cvss_severity(cvss_score)
            results.append((cve_id, cvss_score, severity))

        # Ordena por CVSS score (maior primeiro) e limita a 3 resultados
        results = sorted(results, key=lambda x: x[1], reverse=True)[:3]
        if not results:
            results = [("Nenhuma CVE detectada", 0.0, "Nenhuma")]

        # Armazena no cache
        vuln_cache[cache_key] = results
        return results

    except requests.HTTPError as e:
        if e.response.status_code == 401:
            console.print("[red]Erro: Token de API inválido ou não autorizado. Verifique seu token em https://vulncheck.com/.[/red]")
        return [(f"Erro API: {str(e)}", 0.0, "Nenhuma")]
    except requests.RequestException as e:
        return [(f"Erro API: {str(e)}", 0.0, "Nenhuma")]

# ---------- datamodel + workflow ---------------------------------------------

@dataclass
class HostResult:
    ip: str; details: List[Tuple[str, List[Tuple[str, float, str]]]]

def scan_host(host: str) -> HostResult:
    """Escaneia portas e correlaciona vulnerabilidades (RA-5: escaneamento e correlação)."""
    details = []
    for port, proto in nmap_ports(host):
        banner = banner_tcp(host, port) if proto == "tcp" else banner_udp(host, port)
        # Limita o banner a uma linha, removendo quebras de linha e caracteres de controle
        clean_banner = "".join(c for c in banner if c.isprintable()).replace("\n", " ").replace("\r", " ")
        clean_banner = clean_banner[:50]
        # Verifica vulnerabilidades
        vuln_info = check_vulnerabilities(host, port, proto, clean_banner)
        details.append((f"{port}/{proto} {clean_banner}", vuln_info))
    return HostResult(host, details or [("--", [("Nenhuma CVE detectada", 0.0, "Nenhuma")])])

def workflow(target: str) -> None:
    """Orquestra o escaneamento e exibe resultados (RA-5: relatórios estruturados)."""
    kind = classify(target)
    console.print(f"[yellow]Aviso:[/] testes IoT/OT podem ser intrusivos.")
    hosts = nmap_discover(target, kind)
    if not hosts: console.print("[yellow]Nenhum host ativo.[/]"); return

    results: List[HostResult] = []
    with Progress(SpinnerColumn(), *Progress.get_default_columns(), TimeElapsedColumn()) as prog:
        task = prog.add_task("Scan", total=len(hosts))
        with ThreadPoolExecutor(max_workers=20) as pool:
            futures = {pool.submit(scan_host, h): h for h in hosts}
            for f in as_completed(futures):
                results.append(f.result())
                prog.advance(task)

    table = Table(title="Resultado (NIST 800-53 RA-5)")
    table.add_column("Host", style="cyan", width=15)
    table.add_column("Porta/Banner", style="green", width=50, overflow="ellipsis")
    table.add_column("Vulnerabilidades (CVE/CVSS/Severidade)", style="red", width=40, overflow="ellipsis")
    for r in results:
        for detail, vulns in r.details:
            # Formata a coluna de vulnerabilidades
            vuln_str = "; ".join(f"{cve} ({score:.1f}/{severity})" for cve, score, severity in vulns)
            table.add_row(r.ip, detail, vuln_str)
    console.print(table)
    console.print(f"[green]Hosts ativos: {len(hosts)} | Concluído em {time.perf_counter():.1f}s[/]")

# ---------- cli ----------------------------------------------------------------

def main() -> None:
    p = argparse.ArgumentParser(description="Scanner rápido TI/IoT/OT (NIST 800-53 RA-5)")
    p.add_argument("-t", "--target", required=True, help="192.168.1.0/24 | 10.0.0.5 | domain")
    args = p.parse_args()
    require_root(); require_nmap(); workflow(args.target)

if __name__ == "__main__":
    main()
