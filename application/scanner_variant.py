#!/usr/bin/env python3
"""
VulnScan – scanner + CVE enrichment (TI / OT / IoT)
• nmap + requests + rich
"""

from __future__ import annotations
import argparse, ipaddress, os, re, socket, subprocess, sys, time, string
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from functools import lru_cache
from shutil import which
from typing import List, Tuple

import requests
from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn
from rich.table import Table

console = Console()
_PRINT = set(string.printable)

# ------------------------- config -------------------------------------------
TCP_PORTS = [21, 22, 23, 25, 80, 443, 445, 502, 1883, 3306]
UDP_PORTS = [53, 47808]

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")

CPE_MAP = {
    53:   "cpe:2.3:a:isc:bind:*:*:*:*:*:*:*:*",
    22:   "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    80:   "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
    3306: "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*",
}

CPE_REGEX = [
    (re.compile(r"Apache/?\s*([\d\.]+)", re.I), CPE_MAP[80]),
    (re.compile(r"OpenSSH[_\- ]([\d\.p]+)", re.I), CPE_MAP[22]),
    (re.compile(r"Bind\s9\.", re.I), CPE_MAP[53]),
    (re.compile(r"MySQL|MariaDB", re.I), CPE_MAP[3306]),
]

# ------------------------- util ---------------------------------------------
def require_root() -> None:
    if os.geteuid():
        console.print("[red]Precisa ser root.[/red]")
        sys.exit(1)

def require_nmap() -> None:
    if not which("nmap"):
        console.print("[red]nmap não instalado.[/red]")
        sys.exit(1)

def classify(target: str) -> str:
    for fn, typ in [(ipaddress.ip_network, "network"), (ipaddress.ip_address, "host")]:
        try:
            fn(target, strict=False)
            return typ
        except ValueError:
            pass
    try:
        socket.gethostbyname(target)
        return "url"
    except socket.gaierror:
        console.print(f"[red]Alvo inválido: {target}[/red]")
        sys.exit(1)

def run(cmd: List[str]) -> str:
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode:
        console.print(res.stderr, style="red")
        sys.exit(res.returncode)
    return res.stdout

def sanitize(raw: str, limit: int = 60) -> str:
    if not raw or raw.lower().startswith("err:"):
        return "-"
    clean = "".join(c if c in _PRINT else "." for c in raw)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean[:limit] or "-"

# ------------------------- NVD API ------------------------------------------
HEADERS = {"User-Agent": "vulnscan/1.0"}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

@lru_cache
def fetch_cve(cpe: str) -> tuple[str, float]:
    """
    Retorna (CVE, score) mais crítico para o CPE.
    Procura CVSS v3.1 > v3.0 > v2 entre até 100 resultados.
    """
    params = {
        "cpeName": cpe,
        "resultsPerPage": 100,
        "noRejected": "true",
    }
    try:
        r = requests.get(NVD_URL, params=params, headers=HEADERS, timeout=15)
        if r.status_code in (403, 429):
            return "-", 0.0
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        best_cve, best_score = "-", 0.0
        for v in vulns:
            cve_id = v["cve"]["id"]
            metrics = v["cve"].get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                for m in metrics.get(key, []):
                    score = m["cvssData"]["baseScore"]
                    if score > best_score:
                        best_cve, best_score = cve_id, score
        return best_cve, best_score
    except Exception:
        return "-", 0.0

def banner_to_cpe(port: int, banner: str) -> str | None:
    for rx, cpe in CPE_REGEX:
        if rx.search(banner):
            return cpe
    return CPE_MAP.get(port)

def enrich(port: int, banner: str) -> tuple[str, float]:
    cpe = banner_to_cpe(port, banner)
    return fetch_cve(cpe) if cpe else ("-", 0.0)

# ------------------------- nmap wrappers ------------------------------------
def discover(target: str, kind: str) -> List[str]:
    if kind == "network":
        out = run(["nmap", "-sn", target, "-oG", "-"])
        return [l.split()[1] for l in out.splitlines() if "Status: Up" in l]
    return [target]

def list_ports(host: str) -> List[Tuple[int, str]]:
    tcp = run(["nmap", "-Pn", "-sS", "-p", ",".join(map(str, TCP_PORTS)), "--min-rate", "500", host, "-oG", "-"])
    udp = run(["nmap", "-Pn", "-sU", "-p", ",".join(map(str, UDP_PORTS)), "--min-rate", "1000", host, "-oG", "-"])
    ports: List[Tuple[int, str]] = []
    for line in (tcp + udp).splitlines():
        if "Ports:" not in line:
            continue
        for item in line.split("Ports:")[1].split(","):
            if "/open/" not in item:
                continue
            port, proto = item.split("/")[:3:2]
            ports.append((int(port), proto))
    return ports

# ------------------------- banner grabbing ----------------------------------
def grab_tcp(host: str, port: int, timeout: int = 2) -> str:
    try:
        with socket.create_connection((host, port), timeout) as s:
            if port in (21, 22, 23, 25, 3306):
                return s.recv(120).decode(errors="ignore")
            if port in (80, 443):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                return s.recv(512).decode(errors="ignore")
            if port == 445:
                s.sendall(bytes.fromhex("0000002f"))
                return s.recv(60).hex()
            if port == 502:
                s.sendall(bytes.fromhex("000100000006010300000001"))
                return s.recv(60).hex()
            if port == 1883:
                s.sendall(bytes.fromhex("100f00044d5154540402003c0003abc"))
                return s.recv(60).hex()
            return s.recv(120).decode(errors="ignore")
    except socket.timeout:
        return ""
    except Exception as e:
        return f"err:{e}"

def grab_udp(host: str, port: int, timeout: int = 2) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            if port == 53:
                s.sendto(bytes.fromhex("000001000001000000000000036e733103636f6d0000010001"), (host, port))
            elif port == 47808:
                s.sendto(bytes.fromhex("810b000801002004fffe"), (host, port))
            data, _ = s.recvfrom(120)
            return data.hex()
    except socket.timeout:
        return ""
    except Exception as e:
        return f"err:{e}"

# ------------------------- data classes -------------------------------------
@dataclass
class PortInfo:
    port: str
    proto: str
    banner: str
    cve: str
    cvss: float

@dataclass
class HostRes:
    ip: str
    ports: List[PortInfo]

# ------------------------- workflow -----------------------------------------
def scan(host: str) -> HostRes:
    infos: List[PortInfo] = []
    for p, proto in list_ports(host):
        raw = grab_tcp(host, p) if proto == "tcp" else grab_udp(host, p)
        bann = sanitize(raw)
        cve, score = enrich(p, bann)
        infos.append(PortInfo(str(p), proto, bann, cve, score))
    if not infos:
        infos.append(PortInfo("-", "-", "-", "-", 0.0))
    return HostRes(host, infos)

def workflow(target: str) -> None:
    kind = classify(target)
    console.print("[yellow]Aviso:[/] Varredura pode ser intrusiva.")
    hosts = discover(target, kind)
    if not hosts:
        console.print("[yellow]Nenhum host ativo.[/yellow]")
        return

    start = time.perf_counter()
    results: List[HostRes] = []
    with Progress(SpinnerColumn(), *Progress.get_default_columns(), TimeElapsedColumn()) as prog:
        task = prog.add_task("Scan", total=len(hosts))
        with ThreadPoolExecutor(max_workers=20) as pool:
            fut = {pool.submit(scan, h): h for h in hosts}
            for f in as_completed(fut):
                results.append(f.result())
                prog.advance(task)

    table = Table(title="VulnScan", show_lines=True, box=box.SIMPLE_HEAVY)
    table.add_column("Host", style="bold cyan")
    table.add_column("Porta")
    table.add_column("Proto", justify="center")
    table.add_column("Banner", style="green", overflow="fold")
    table.add_column("CVE", style="red")
    table.add_column("CVSS", justify="right")

    for r in results:
        first = True
        for p in r.ports:
            table.add_row(
                r.ip if first else "",
                p.port,
                p.proto,
                p.banner,
                p.cve,
                f"{p.cvss:.1f}" if p.cvss else "-"
            )
            first = False

    console.print(table)
    console.print(f"[green]Hosts: {len(hosts)} | Tempo: {time.perf_counter() - start:.1f}s[/green]")

# ------------------------- CLI ---------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="Scanner TI/OT/IoT com CVE enrichment")
    parser.add_argument("-t", "--target", required=True, help="Ex.: 192.168.1.0/24 ou scanme.nmap.org")
    args = parser.parse_args()

    require_root()
    require_nmap()
    workflow(args.target)

if __name__ == "__main__":
    main()
