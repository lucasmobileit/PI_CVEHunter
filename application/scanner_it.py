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
import ssl  # Para lidar com HTTPS de forma mais robusta

# --- Configuração da Console ---
console = Console()


def validate_input(target):
    """Valida se o alvo é uma rede CIDR, um host IP, ou uma URL."""
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
        # Tenta resolver a URL para IP
        socket.gethostbyname(target)
        return "url"
    except socket.gaierror:
        console.print(
            f"[red][!] Erro: Alvo '{target}' inválido. Use formato como '192.168.1.0/24', '192.168.1.1' ou 'scanme.nmap.org'.[/red]")
        return None


def check_nmap_installed():
    """Verifica se o nmap está instalado."""
    return subprocess.run(["which", "nmap"], capture_output=True).stdout != b""


def grab_banner_tcp(host, port, timeout=3):
    """Executa banner grabbing para portas TCP de TI."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # --- Lógica de Banner Grabbing Específica por Porta TCP ---
        if port == 21:  # FTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"FTP: {banner[:70]}" if banner else "FTP: No banner"

        elif port == 22:  # SSH
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"SSH: {banner[:70]}" if banner else "SSH: No banner"

        elif port == 23:  # Telnet
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"Telnet: {banner[:70]}" if banner else "Telnet: No banner"

        elif port == 25:  # SMTP
            sock.sendall(b"EHLO example.com\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"SMTP: {banner[:70]}" if banner else "SMTP: No banner"

        elif port == 80:  # HTTP
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: IT-Scanner\r\nConnection: close\r\n\r\n"
            sock.send(request.encode('utf-8'))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            for line in banner.splitlines():
                if line.lower().startswith('server:'):
                    return f"HTTP: {line.split(':', 1)[1].strip()[:70]}"
            return "HTTP: No server banner"

        elif port == 110:  # POP3
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"POP3: {banner[:70]}" if banner else "POP3: No banner"

        elif port == 135:  # RPC (Geralmente não tem banner de texto claro)
            return "RPC: Service detected"

        elif port == 143:  # IMAP
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"IMAP: {banner[:70]}" if banner else "IMAP: No banner"

        elif port == 443:  # HTTPS
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert['subject'])
                    common_name = subject.get('commonName', 'N/A')
                    return f"HTTPS: CommonName={common_name[:70]}"
            except ssl.SSLError as ssl_e:
                return f"HTTPS: TLS Error ({str(ssl_e)[:70]})"
            except Exception as e:
                return f"HTTPS: Connection successful (TLS handshake failed or no cert data: {str(e)[:70]})"

        elif port == 445:  # SMB
            smb_packet = bytes.fromhex("0000002f.ff534d42720000000000000000000000000000000000000000000000")
            sock.send(smb_packet)
            banner = sock.recv(1024).hex()
            return f"SMB: Negotiated (hex: {banner[:70]})" if banner else "SMB: No response"

        elif port == 1433:  # MS SQL Server (TDS)
            banner = sock.recv(1024).hex()
            return f"MSSQL: Detected (hex: {banner[:70]})" if banner else "MSSQL: No response"

        elif port == 3306:  # MySQL
            banner = sock.recv(1024)
            try:
                version_info = banner[5:].decode('utf-8', errors='ignore').split('\0')[0]
                return f"MySQL: {version_info[:70]}"
            except IndexError:
                return f"MySQL: Detected (hex: {banner.hex()[:70]})" if banner else "MySQL: No banner"

        elif port == 3389:  # RDP
            return "RDP: Service detected"

        elif port == 5432:  # PostgreSQL
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"PostgreSQL: {banner[:70]}" if banner else "PostgreSQL: No banner"

        elif port == 5900:  # VNC
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"VNC: {banner[:70]}" if banner else "VNC: No banner"

        elif port == 6379:  # Redis
            sock.sendall(b"INFO\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner.startswith("+OK") or banner.startswith("$"):
                return f"Redis: {banner.splitlines()[0][:70]}" if banner else "Redis: Detected (info sent)"
            return f"Redis: {banner[:70]}" if banner else "Redis: No banner"

        elif port == 8080:  # HTTP Alt (trata como HTTP)
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: IT-Scanner\r\nConnection: close\r\n\r\n"
            sock.send(request.encode('utf-8'))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            for line in banner.splitlines():
                if line.lower().startswith('server:'):
                    return f"HTTP (Alt): {line.split(':', 1)[1].strip()[:70]}"
            return "HTTP (Alt): No server banner"

        # --- Banner Grabbing Genérico (fallback para portas não mapeadas) ---
        sock.settimeout(1)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner:
            return f"Generic TCP: {banner[:70]}"
        return "Generic TCP: No immediate banner"

    except socket.timeout:
        return "Timeout"
    except ConnectionRefusedError:
        return "Connection Refused"
    except Exception as e:
        return f"Error: {str(e)[:70]}"
    finally:
        sock.close()


def grab_banner_udp(host, port, timeout=3):
    """Executa banner grabbing para portas UDP de TI."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # --- Lógica de Banner Grabbing Específica por Porta UDP ---
        if port == 53:  # DNS
            dns_packet = bytes.fromhex("000001000001000000000000076578616d706c6503636f6d0000010001")
            sock.sendto(dns_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"DNS: Response (hex: {banner.hex()[:70]})" if banner else "DNS: No response"

        elif port == 67:  # DHCP Server
            return "DHCP Server: Detected"

        elif port == 68:  # DHCP Client
            return "DHCP Client: Detected"

        elif port == 69:  # TFTP
            tftp_packet = bytes.fromhex("0001000000000000")
            sock.sendto(tftp_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"TFTP: Response (hex: {banner.hex()[:70]})" if banner else "TFTP: No response"

        elif port == 123:  # NTP
            ntp_packet = bytes.fromhex(
                "e300040000000000000000000000000000000000000000000000000000000000000000000000000000000000")
            sock.sendto(ntp_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"NTP: Response (hex: {banner.hex()[:70]})" if banner else "NTP: No response"

        elif port == 137:  # NetBIOS Name Service
            nbstat_packet = bytes.fromhex(
                "804b0000000100000000000020434b4e4f4c49434143414341434143414341434143414341434143414341434100000000")
            sock.sendto(nbstat_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"NetBIOS Name: Response (hex: {banner.hex()[:70]})" if banner else "NetBIOS Name: No response"

        elif port == 138:  # NetBIOS Datagram Service
            return "NetBIOS Datagram: Detected"

        elif port == 161:  # SNMP
            snmp_packet = bytes.fromhex(
                "302602010104067075626c6963a019020101020100020100300e300c06082b060102010101000500")
            sock.sendto(snmp_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            try:
                decoded_banner = banner.decode('utf-8', errors='ignore').strip()
                return f"SNMP: {decoded_banner[:70]}" if decoded_banner else f"SNMP: Response (hex: {banner.hex()[:70]})"
            except Exception:
                return f"SNMP: Response (hex: {banner.hex()[:70]})" if banner else "SNMP: No response"

        elif port == 162:  # SNMP Trap
            return "SNMP Trap: Detected"

        elif port == 500:  # ISAKMP/IKE
            ike_packet = bytes.fromhex("00000000000000000000000001100200000000000000000000000000")
            sock.sendto(ike_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"ISAKMP/IKE: Response (hex: {banner.hex()[:70]})" if banner else "ISAKMP/IKE: No response"

        elif port == 514:  # Syslog
            return "Syslog: Detected"

        elif port == 4500:  # IPSec NAT-T
            return "IPSec NAT-T: Detected"

        return "Generic UDP: Service detected (no specific banner probe)"

    except socket.timeout:
        return "Timeout"
    except Exception as e:
        return f"Error: {str(e)[:70]}"
    finally:
        sock.close()


def discover_hosts(target, input_type, output_file="hosts_ativos.txt", verbose=False):
    """Descobre hosts ativos e enumera portas com banner grabbing."""
    active_hosts = []
    start_time = time.time()

    try:
        if not check_nmap_installed():
            console.print("[red][!] Erro: Nmap não está instalado. Instale com 'sudo apt install nmap'.[/red]")
            return []

        if os.geteuid() != 0:
            console.print("[red][!] Erro: Este script requer permissões de administrador. Execute com sudo.[/red]")
            return []

        if not input_type:
            return []

        console.print(f"[cyan][*] Iniciando varredura no alvo {target} ({input_type})...[/cyan]")

        if input_type == "network":
            command = f"nmap -sn -PR {target} -oG - | awk '/Up/{{print $2}}' > {output_file}"
        else:
            command = f"nmap -sn {target} -oG - | awk '/Up/{{print $2}}' > {output_file}"

        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            console.print(f"[yellow][!] Aviso do Nmap na descoberta de hosts: {result.stderr.strip()}[/yellow]")

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                active_hosts = [line.strip() for line in f.readlines() if line.strip()]
        else:
            console.print(
                f"[yellow][!] Arquivo {output_file} não foi criado ou está vazio. Nenhum host encontrado ativo no ping scan.[/yellow]")
            # Se for um host/URL único e não foi detectado, tenta escanear o IP resolvido diretamente
            if input_type != "network":
                try:
                    resolved_ip = str(ipaddress.ip_address(target))
                except ValueError:
                    try:
                        resolved_ip = socket.gethostbyname(target)
                    except socket.gaierror:
                        console.print(f"[red][!] Não foi possível resolver o IP para '{target}'.[/red]")
                        return []
                active_hosts = [resolved_ip]
            else:
                return []

        tcp_ports_list = [
            "21", "22", "23", "25", "80", "110", "135", "139", "143", "443", "445",
            "1433", "3306", "3389", "5432", "5900", "6379", "8080"
        ]
        udp_ports_list = [
            "53", "67", "68", "69", "123", "137", "138", "161", "162", "500",
            "514", "4500"
        ]

        console.print("[cyan][*] Enumerando portas TCP/UDP para hosts ativos e coletando banners...[/cyan]")

        host_details = []
        for host in track(active_hosts, description="Varrendo e coletando banners"):
            ports_info = []

            tcp_command = f"nmap -sS --max-rate 500 --scan-delay 0.5s -p {','.join(tcp_ports_list)} {host} -oN -"
            tcp_result = subprocess.run(tcp_command, shell=True, capture_output=True, text=True)

            udp_command = f"nmap -sU --max-rate 1000 --scan-delay 0.5s -p {','.join(udp_ports_list)} {host} -oN -"
            udp_result = subprocess.run(udp_command, shell=True, capture_output=True, text=True)

            open_ports = []
            for line in tcp_result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split('/')[0].strip()
                    open_ports.append((port, "tcp"))
            for line in udp_result.stdout.splitlines():
                if "/udp" in line and ("open" in line or "open|filtered" in line):
                    port = line.split('/')[0].strip()
                    open_ports.append((port, "udp"))

            for port, proto in open_ports:
                port_int = int(port)
                if proto == "tcp":
                    banner = grab_banner_tcp(host, port_int)
                else:
                    banner = grab_banner_udp(host, port_int)
                ports_info.append(f"{port}/{proto}: {banner}")

            if not ports_info:
                ports_info.append("Nenhuma porta aberta detectada")

            host_details.append({"host": host, "ports": "; ".join(ports_info)})

            with open(output_file, "a") as f:
                f.write(f"\nHost: {host}\nPorts/Services: {'; '.join(ports_info)}\n")

        table = Table(title="Hosts Ativos Encontrados (Redes de TI) - Detalhes da Varredura")
        table.add_column("IP", style="cyan", width=15)
        table.add_column("Porta/Proto", style="magenta", width=15)
        table.add_column("Serviço (Banner)", style="green", width=60, overflow="fold")

        for detail in host_details:
            if detail["ports"] == "Nenhuma porta aberta detectada":
                table.add_row(detail["host"], "-", detail["ports"])
            else:
                for port_info in detail["ports"].split("; "):
                    parts = port_info.split(": ", 1)
                    port_proto = parts[0]
                    banner_text = parts[1] if len(parts) > 1 else ""
                    table.add_row(detail["host"], port_proto, banner_text)

        console.print(table)

        end_time = time.time()
        console.print(f"[green][+] Varredura concluída em {end_time - start_time:.2f} segundos.[/green]")
        console.print(f"[green][+] Total de hosts ativos: {len(active_hosts)}[/green]")
        console.print(f"[green][+] Resultados salvos em: {output_file}[/green]")

        return active_hosts

    except KeyboardInterrupt:
        console.print("[yellow][!] Varredura interrompida pelo usuário.[/yellow]")
        return []
    except Exception as e:
        console.print(f"[red][!] Erro inesperado no discover_hosts: {e}[/red]")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Script para varredura de hosts com Nmap e banner grabbing (otimizado para TI).")
    parser.add_argument("-t", "--target", type=str,
                        help="Alvo para varredura (ex.: 192.168.1.0/24, 192.168.1.1, server.local)")
    parser.add_argument("-o", "--output", type=str, default="hosts_ativos.txt", help="Arquivo de saída")
    parser.add_argument("-v", "--verbose", action="store_true", help="Ativar logs detalhados (apenas para este script)")

    args = parser.parse_args()

    target = args.target
    if not target:
        console.print(
            "[cyan][*] Digite o alvo para varredura (ex.: 192.168.1.0/24, 192.168.1.1, server.local): [/cyan]", end="")
        target = input().strip()

    if not target:
        console.print("[red][!] Erro: Nenhum alvo fornecido.[/red]")
        sys.exit(1)

    input_type = validate_input(target)
    if not input_type:
        sys.exit(1)

    if args.verbose:
        os.environ['PYTHON_SCANNER_VERBOSE'] = '1'
    else:
        os.environ['PYTHON_SCANNER_VERBOSE'] = '0'

    hosts = discover_hosts(target, input_type, output_file=args.output, verbose=args.verbose)
    if hosts:
        console.print(f"[green][+] Hosts encontrados: {hosts}[/green]")
    else:
        console.print("[yellow][!] Nenhum host ativo encontrado.[/yellow]")


if __name__ == "__main__":
    main()
