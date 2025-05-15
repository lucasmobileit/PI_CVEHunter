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

def validate_input(target):
    """Valida se o alvo é uma rede CIDR, um host IP, ou uma URL."""
    console = Console()
    
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
        console.print(f"[red][!] Erro: Alvo '{target}' inválido. Use formato como '192.168.1.0/24', '192.168.1.1' ou 'scanme.nmap.org'.[/red]")
        return None

def check_nmap_installed():
    """Verifica se o nmap está instalado."""
    return subprocess.run(["which", "nmap"], capture_output=True).stdout != b""

def grab_banner_tcp(host, port, timeout=3):
    """Executa banner grabbing para portas TCP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        if port == 21:  # FTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"FTP: {banner[:50]}" if banner else "FTP: No banner"
        
        elif port == 22:  # SSH
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"SSH: {banner[:50]}" if banner else "SSH: No banner"
        
        elif port == 23:  # Telnet
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"Telnet: {banner[:50]}" if banner else "Telnet: No banner"
        
        elif port in [80, 443]:  # HTTP/HTTPS
            request = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n"
            sock.send(request.encode('utf-8'))
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            for line in banner.splitlines():
                if line.lower().startswith('server:'):
                    return f"HTTP: {line[:50]}"
            return f"HTTP: No server banner"
        
        elif port == 25:  # SMTP
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"SMTP: {banner[:50]}" if banner else "SMTP: No banner"
        
        elif port == 445:  # SMB
            smb_packet = bytes.fromhex("0000002f.ff534d42720000000000000000000000000000000000000000000000")
            sock.send(smb_packet)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"SMB: {banner[:50]}" if banner else "SMB: No response"
        
        elif port == 3306:  # MySQL
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return f"MySQL: {banner[:50]}" if banner else "MySQL: No banner"
        
        elif port == 502:  # Modbus
            modbus_packet = bytes.fromhex("000100000006010300000001")
            sock.send(modbus_packet)
            banner = sock.recv(1024).hex()
            return f"Modbus: {banner[:20]}" if banner else "Modbus: No response"
        
        elif port == 1883:  # MQTT
            mqtt_packet = bytes.fromhex("100f00044d5154540402003c0003abc")
            sock.send(mqtt_packet)
            banner = sock.recv(1024).hex()
            return f"MQTT: {banner[:20]}" if banner else "MQTT: No response"
        
        else:
            return "Unknown service"
    
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        sock.close()

def grab_banner_udp(host, port, timeout=3):
    """Executa banner grabbing para portas UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        if port == 53:  # DNS
            dns_packet = bytes.fromhex("000001000001000000000000036e733103636f6d0000010001")
            sock.sendto(dns_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"DNS: Response {banner.hex()[:20]}" if banner else "DNS: No response"
        
        elif port == 47808:  # BACnet
            bacnet_packet = bytes.fromhex("810b000801002004fffe")
            sock.sendto(bacnet_packet, (host, port))
            banner, _ = sock.recvfrom(1024)
            return f"BACnet: {banner.hex()[:20]}" if banner else "BACnet: No response"
        
        return "Unknown UDP service"
    
    except Exception as e:
        return f"Error: {str(e)}"
    finally:
        sock.close()

def discover_hosts(target, input_type, output_file="hosts_ativos.txt", verbose=False):
    """Descobre hosts ativos e enumera portas com banner grabbing."""
    console = Console()
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

        console.print(f"[yellow][!] Aviso: Varreduras em dispositivos IoT/OT podem causar interrupções. Teste em ambiente controlado.[/yellow]")
        console.print(f"[cyan][*] Iniciando varredura no alvo {target} ({input_type})...[/cyan]")

        # Descoberta de hosts
        if input_type == "network":
            command = f"nmap -sn -PR {target} -oG - | awk '/Up/{{print $2}}' > {output_file}"
        else:
            command = f"nmap -sn {target} -oG - | awk '/Up/{{print $2}}' > {output_file}"

        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            console.print(f"[red][!] Erro ao executar Nmap: {result.stderr}[/red]")
            return []

        if os.path.exists(output_file):
            with open(output_file, "r") as f:
                active_hosts = [line.strip() for line in f.readlines() if line.strip()]
        else:
            console.print(f"[yellow][!] Arquivo {output_file} não foi criado. Nenhum host encontrado.[/yellow]")
            return []

        # Enumeração de portas
        host_details = []
        tcp_ports = ["21", "22", "23", "25", "80", "443", "445", "502", "1883", "3306"]
        udp_ports = ["53", "47808"]
        console.print("[cyan][*] Enumerando portas TCP/UDP para hosts ativos...[/cyan]")
        
        for host in track(active_hosts, description="Enumeração de portas"):
            ports_info = []
            
            # Varredura TCP SYN
            tcp_command = f"nmap -sS --max-rate 500 --scan-delay 0.1s -p {','.join(tcp_ports)} {host} -oN -"
            tcp_result = subprocess.run(tcp_command, shell=True, capture_output=True, text=True)
            
            # Varredura UDP
            udp_command = f"nmap -sU --max-rate 1000 --scan-delay 0.1s -p {','.join(udp_ports)} {host} -oN -"
            udp_result = subprocess.run(udp_command, shell=True, capture_output=True, text=True)
            
            # Parsing de portas abertas
            open_ports = []
            for line in tcp_result.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    port = line.split('/')[0].strip()
                    open_ports.append((port, "tcp"))
            for line in udp_result.stdout.splitlines():
                if "/udp" in line and "open" in line:
                    port = line.split('/')[0].strip()
                    open_ports.append((port, "udp"))
            
            # Banner grabbing para portas abertas
            for port, proto in open_ports:
                port_int = int(port)
                if proto == "tcp":
                    banner = grab_banner_tcp(host, port_int)
                else:
                    banner = grab_banner_udp(host, port_int)
                ports_info.append(f"{port}/{proto}: {banner}")
            
            # Se nenhuma porta aberta, registrar como tal
            if not ports_info:
                ports_info.append("Nenhuma porta aberta detectada")
            
            host_details.append({"host": host, "ports": "; ".join(ports_info)})
            
            # Salvar no arquivo
            with open(output_file, "a") as f:
                f.write(f"\nHost: {host}\nPorts/Services: {'; '.join(ports_info)}\n")

        # Exibe tabela com resultados
        table = Table(title="Hosts Ativos Encontrados (TI/IoT/OT)")
        table.add_column("IP", style="cyan", width=15)
        table.add_column("Porta/Proto", style="magenta", width=15)
        table.add_column("Serviço (Banner)", style="green", width=50, overflow="fold")
        for detail in host_details:
            if detail["ports"] == "Nenhuma porta aberta detectada":
                table.add_row(detail["host"], "-", detail["ports"])
            else:
                for port_info in detail["ports"].split("; "):
                    port_proto, banner = port_info.split(": ", 1)
                    table.add_row(detail["host"], port_proto, banner)
        
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
        console.print(f"[red][!] Erro inesperado: {e}[/red]")
        return []

def main():
    parser = argparse.ArgumentParser(description="Script para varredura de hosts com Nmap e banner grabbing (otimizado para TI/IoT/OT).")
    parser.add_argument("-t", "--target", type=str, help="Alvo para varredura (ex.: 192.168.1.0/24, 192.168.1.1, metasploitable.local)")
    parser.add_argument("-o", "--output", type=str, default="hosts_ativos.txt", help="Arquivo de saída")
    parser.add_argument("-v", "--verbose", action="store_true", help="Ativar logs detalhados")

    args = parser.parse_args()

    console = Console()

    target = args.target
    if not target:
        console.print("[cyan][*] Digite o alvo para varredura (ex.: 192.168.1.0/24, 192.168.1.1, metasploitable.local): [/cyan]", end="")
        target = input().strip()

    if not target:
        console.print("[red][!] Erro: Nenhum alvo fornecido.[/red]")
        sys.exit(1)

    input_type = validate_input(target)
    if not input_type:
        sys.exit(1)

    hosts = discover_hosts(target, input_type, output_file=args.output, verbose=args.verbose)
    if hosts:
        console.print(f"[green][+] Hosts encontrados: {hosts}[/green]")
    else:
        console.print("[yellow][!] Nenhum host ativo encontrado.[/yellow]")

if __name__ == "__main__":
    main()
