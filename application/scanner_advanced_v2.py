import subprocess
import os
import sys
import argparse
import time
import ipaddress
import socket
import threading
import json
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.logging import RichHandler
from scapy.all import ARP, Ether, srp, IP, TCP, UDP, sr1, ICMP

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("scanner")

# Define uma classe singleton para configurações globais
class ScannerConfig:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ScannerConfig, cls).__new__(cls)
            cls._instance.verbose = False
            cls._instance.passive_only = False
            cls._instance.max_threads = 50
            cls._instance.scan_timeout = 3
            cls._instance.scan_rate = 100
            cls._instance.console = Console()
        return cls._instance

config = ScannerConfig()

@contextmanager
def graceful_exit():
    """Garante saída limpa ao capturar interrupções."""
    try:
        yield
    except KeyboardInterrupt:
        config.console.print("[yellow][!] Varredura interrompida pelo usuário. Finalizando...[/yellow]")
        time.sleep(1)
        sys.exit(0)
    except Exception as e:
        config.console.print(f"[red][!] Erro inesperado: {str(e)}[/red]")
        if config.verbose:
            logger.exception("Detalhes do erro:")
        sys.exit(1)

def validate_input(target):
    """Valida se o alvo é uma rede CIDR, IP ou URL."""
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
        config.console.print(f"[red][!] Alvo '{target}' inválido. Use '192.168.1.0/24', '192.168.1.1' ou 'scanme.nmap.org'.[/red]")
        return None

def check_prerequisites():
    """Verifica se as ferramentas necessárias estão instaladas."""
    tools = {"tcpdump": "sudo apt install tcpdump"}  # nmap removido, pois usamos Scapy
    missing = [tool for tool, cmd in tools.items() if not subprocess.run(["which", tool], capture_output=True).stdout]
    if missing:
        config.console.print("[red][!] Ferramentas ausentes:[/red]")
        for tool in missing:
            config.console.print(f"[yellow]  - {tool} (instale com: {tools[tool]})[/yellow]")
        return False
    return True

def is_sensitive_device(port_info):
    """Detecta dispositivos sensíveis com base em banners."""
    sensitive_indicators = [
        "modbus", "bacnet", "mqtt", "plc", "scada", "dnp3", "iec", "siemens", "schneider", 
        "rockwell", "mitsubishi", "honeywell", "profinet", "ethercat", "opc ua"
    ]
    return any(indicator in port_info.lower() for indicator in sensitive_indicators)

def safe_subprocess_run(command, shell=True, capture_output=True, text=True, timeout=60):
    """Executa comandos subprocess com segurança."""
    try:
        return subprocess.run(command, shell=shell, capture_output=capture_output, text=text, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout após {timeout}s: {command}")
        return None
    except Exception as e:
        logger.error(f"Erro ao executar '{command}': {str(e)}")
        return None

def grab_banner_tcp(host, port, timeout=None):
    """Coleta banners de serviços TCP."""
    timeout = timeout if timeout is not None else config.scan_timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) != 0:
            return "Porta fechada ou filtrada"
        
        proto_handlers = {
            21: {"name": "FTP", "request": None},
            22: {"name": "SSH", "request": None},
            80: {"name": "HTTP", "request": f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"},
            443: {"name": "HTTPS", "request": f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"},
            502: {"name": "Modbus", "request": bytes.fromhex("000100000006010300000001")},
            34962: {"name": "Profinet", "request": bytes.fromhex("02F08000")},
        }
        handler = proto_handlers.get(port, {"name": "Unknown", "request": None})
        
        if handler["request"]:
            sock.send(handler["request"] if isinstance(handler["request"], bytes) else handler["request"].encode('utf-8'))
        
        banner = b""
        start_time = time.time()
        while time.time() - start_time < timeout:
            chunk = sock.recv(1024)
            if not chunk:
                break
            banner += chunk
            if len(banner) > 4096:
                break
        
        if banner:
            text_banner = banner.decode('utf-8', errors='ignore').strip()[:100] + ("..." if len(banner) > 100 else "")
            return f"{handler['name']}: {text_banner}"
        return f"{handler['name']}: Sem resposta"
    except Exception as e:
        return f"Erro: {str(e)}"
    finally:
        sock.close()

def grab_banner_udp(host, port, timeout=None):
    """Coleta banners de serviços UDP."""
    timeout = timeout if timeout is not None else config.scan_timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        proto_handlers = {
            53: {"name": "DNS", "request": bytes.fromhex("ab0d01000001000000000000076578616d706c6503636f6d0000010001")},
            123: {"name": "NTP", "request": bytes.fromhex("230300040000000000000000")},
        }
        handler = proto_handlers.get(port, {"name": "Unknown UDP", "request": None})
        
        if not handler["request"]:
            return f"{handler['name']}: Sem payload disponível"
        
        sock.sendto(handler["request"] if isinstance(handler["request"], bytes) else handler["request"].encode('utf-8'), (host, port))
        banner, _ = sock.recvfrom(1024)
        
        text_banner = banner.decode('utf-8', errors='ignore').strip()[:50]
        return f"{handler['name']}: {text_banner}"
    except socket.timeout:
        return f"{handler['name']}: Timeout"
    except Exception as e:
        return f"Erro UDP: {str(e)}"
    finally:
        sock.close()

def passive_sniffing(target, duration=30):
    """Detecta hosts passivamente usando tcpdump."""
    if validate_input(target) != "network":
        return {}
    
    interface = get_interface_for_target(target)
    if not interface:
        config.console.print("[yellow][!] Interface não encontrada. Pulando modo passivo.[/yellow]")
        return {}
    
    config.console.print(f"[cyan][*] Sniffing passivo por {duration}s na interface {interface}...[/cyan]")
    output_file = f"passive_{int(time.time())}.pcap"
    command = f"sudo tcpdump -i {interface} -nn -w {output_file} -G {duration} -W 1"
    
    try:
        subprocess.Popen(command, shell=True)
        time.sleep(duration + 1)
        
        result = safe_subprocess_run(f"tcpdump -nn -r {output_file} | awk '{{print $3}}' | cut -d. -f1-4 | sort | uniq")
        if result and result.returncode == 0:
            target_network = ipaddress.ip_network(target, strict=False)
            active_hosts = {ip.split(":")[0]: {"detection": "passive"} for ip in result.stdout.splitlines() if ip and ipaddress.ip_address(ip.split(":")[0]) in target_network}
            os.remove(output_file)
            return active_hosts
    except Exception as e:
        config.console.print(f"[red][!] Erro no sniffing passivo: {str(e)}[/red]")
    return {}

def get_interface_for_target(target):
    """Determina a interface de rede para o alvo."""
    result = safe_subprocess_run("ip route")
    if result and result.returncode == 0:
        target_network = ipaddress.ip_network(target, strict=False)
        for line in result.stdout.splitlines():
            if "dev" in line:
                parts = line.split()
                if parts[0] == "default" or (ipaddress.ip_network(parts[0], strict=False).overlaps(target_network)):
                    return parts[parts.index("dev") + 1]
    return None

def discover_hosts(target, input_type, output_file="scan_results.json", passive=False):
    if not check_prerequisites() or os.geteuid() != 0 or not input_type:
        config.console.print("[red][!] Pré-requisitos ou permissões insuficientes.[/red]")
        return {}
    
    config.console.print("[yellow][!] Varreduras em IoT/OT podem causar interrupções. Teste em ambiente controlado.[/yellow]")
    
    active_hosts = {}
    
    if passive:
        passive_hosts = passive_sniffing(target, 30)
        active_hosts.update(passive_hosts)
        
        if passive_hosts:
            config.console.print(f"[green][+] Detectados {len(passive_hosts)} hosts via monitoramento passivo.[/green]")
    
    if not active_hosts or not passive:
        config.console.print(f"[cyan][*] Iniciando varredura ativa no alvo {target} ({input_type})...[/cyan]")
        
        if input_type == "network":
            arp = ARP(pdst=target)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            result = srp(packet, timeout=3, verbose=0)[0]
            
            for sent, received in result:
                ip = received.psrc
                active_hosts[ip] = {"detection": "active"}
        else:
            active_hosts[target] = {"detection": "active"}
    
    if not active_hosts:
        config.console.print("[yellow][!] Nenhum host detectado.[/yellow]")
        return {}
    
    tcp_ports = [21, 22, 23, 25, 80, 443, 445, 502, 102, 1883, 2222, 3306, 8080, 8443, 9600, 20000, 44818, 47808]
    udp_ports = [53, 67, 68, 69, 123, 161, 1900, 5353, 47808, 20000]
    
    all_results = {}
    with ThreadPoolExecutor(max_workers=config.max_threads) as executor:
        future_to_host = {
            executor.submit(scan_host_ports_scapy, host, tcp_ports, udp_ports): host 
            for host in active_hosts.keys()
        }
        
        for future in track(future_to_host, description="[cyan]Escaneando hosts[/cyan]"):
            host = future_to_host[future]
            try:
                port_results = future.result()
                all_results[host] = {
                    "detection": active_hosts[host]["detection"],
                    "ports": port_results
                }
            except Exception as e:
                if config.verbose:
                    logger.error(f"Erro ao escanear {host}: {str(e)}")
    
    display_scan_results(all_results)
    save_results(all_results, output_file)
    generate_legacy_output(all_results, output_file.replace('.json', '.txt'))
    
    config.console.print(f"[green][+] Varredura concluída em {time.time() - time.time():.2f}s. Resultados salvos em {output_file}[/green]")
    return all_results

def scan_host_ports_scapy(host, tcp_ports, udp_ports):
    ports_info = []
    
    for port in tcp_ports:
        time.sleep(1 / config.scan_rate)
        packet = IP(dst=host) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                rst_packet = IP(dst=host) / TCP(dport=port, flags="R")
                sr(rst_packet, timeout=1, verbose=0)
                banner = grab_banner_tcp(host, port)
                ports_info.append({
                    "port": port,
                    "protocol": "tcp",
                    "banner": banner,
                    "sensitive": is_sensitive_device(banner)
                })
    
    for port in udp_ports:
        time.sleep(1 / config.scan_rate)
        packet = IP(dst=host) / UDP(dport=port)
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and not (response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1, 2, 9, 10, 13]):
            banner = grab_banner_udp(host, port)
            ports_info.append({
                "port": port,
                "protocol": "udp",
                "banner": banner,
                "sensitive": is_sensitive_device(banner)
            })
    
    return ports_info

def display_scan_results(results):
    """Exibe resultados em uma tabela."""
    table = Table(title="Hosts Ativos (TI/IoT/OT)")
    table.add_column("IP", style="cyan")
    table.add_column("Detecção", style="blue")
    table.add_column("Porta/Proto", style="magenta")
    table.add_column("Serviço (Banner)", style="green")
    table.add_column("Sensível", style="yellow")
    
    for host, details in results.items():
        for i, port_info in enumerate(details.get("ports", [])):
            table.add_row(
                host if i == 0 else "",
                details["detection"] if i == 0 else "",
                f"{port_info['port']}/{port_info['protocol']}",
                port_info["banner"],
                "⚠️" if port_info["sensitive"] else ""
            )
    config.console.print(table)

def save_results(results, output_file):
    """Salva resultados em JSON."""
    try:
        with open(output_file, "w") as f:
            json.dump({"metadata": {"scan_time": datetime.now().isoformat(), "version": "1.0.0"}, "hosts": results}, f, indent=2)
    except Exception as e:
        config.console.print(f"[red][!] Erro ao salvar: {str(e)}[/red]")

def generate_legacy_output(results, output_file):
    """Gera saída em formato texto legado."""
    with open(output_file, "w") as f:
        f.write(f"# Resultados da Varredura - {datetime.now().isoformat()}\n\n")
        for host, details in results.items():
            f.write(f"Host: {host}\nDetecção: {details['detection']}\n")
            f.write(f"Portas: {', '.join(f'{p['port']}/{p['protocol']}: {p['banner']}' for p in details['ports'])}\n\n")

def main():
    parser = argparse.ArgumentParser(description="Scanner de rede avançado para ambientes IT/OT/IoT.")
    parser.add_argument("-t", "--target", required=True, help="Alvo (ex.: 192.168.1.0/24)")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Arquivo de saída")
    parser.add_argument("-p", "--passive", action="store_true", help="Usar modo passivo")
    parser.add_argument("-v", "--verbose", action="store_true", help="Logs detalhados")
    parser.add_argument("--threads", type=int, default=50, help="Máximo de threads")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout (s)")
    parser.add_argument("--scan-rate", type=int, default=100, help="Taxa de pacotes/s")
    
    args = parser.parse_args()
    
    config.verbose = args.verbose
    config.max_threads = args.threads
    config.scan_timeout = args.timeout
    config.scan_rate = args.scan_rate
    
    input_type = validate_input(args.target)
    if input_type:
        with graceful_exit():
            discover_hosts(args.target, input_type, args.output, args.passive)

if __name__ == "__main__":
    main()
