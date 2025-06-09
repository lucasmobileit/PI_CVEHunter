import re
import socket
import subprocess
import time
import os
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import track
from parsing import parse_nmap_xml_output, parse_nmap_sv_xml_details
from banner_grabbing import grab_banner_tcp, grab_banner_udp

console = Console()

def discover_hosts(target, input_type, output_file="scan_results.txt"):
    active_hosts_ips = []
    start_time = time.time()
    try:
        allow_no_root = '--no-root-check' in sys.argv or os.environ.get("ALLOW_NO_ROOT") == "1"
        if os.geteuid() != 0 and not allow_no_root:
            console.print("[red][!] Erro: Requer root para Nmap -sS. Use --no-root-check para modo limitado.[/red]")
            return []
        elif os.geteuid() != 0 and allow_no_root:
            console.print("[yellow][!] Aviso: Rodando sem root. Nmap usará -sT.[/yellow]")
        if not input_type:
            return []

        console.print(f"[cyan][*] Iniciando descoberta em {target} ({input_type})...[/cyan]")
        nmap_discover_cmd = ["nmap", "-sn", "-T4", target, "-oG", "-"]
        result = subprocess.run(nmap_discover_cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0 and result.stderr:
            console.print(f"[yellow][!] Nmap (descoberta): {result.stderr.strip()}[/yellow]")
        if result.stdout:
            for line in result.stdout.splitlines():
                if "Status: Up" in line:
                    match = re.search(r"Host:\s*([0-9a-fA-F.:]+)", line)
                    if match:
                        active_hosts_ips.append(match.group(1))
        if not active_hosts_ips:
            if input_type != "network":
                try:
                    resolved_ip = socket.gethostbyname(target)
                    console.print(
                        f"[yellow][!] Ping scan falhou para '{target}', tentando IP resolvido: {resolved_ip}[/yellow]")
                    active_hosts_ips = [resolved_ip]
                except socket.gaierror:
                    console.print(f"[red][!] Não foi possível resolver IP para '{target}'.[/red]")
                    return []
            else:
                console.print(f"[yellow][!] Nenhum host ativo encontrado em {target}.[/yellow]")
                return []
        console.print(f"[green][+] Hosts ativos preliminares: {active_hosts_ips}[/green]")

        common_tcp_ports = "21,22,23,25,80,110,135,139,143,445,1433,3306,3389,5432,5900,6379,8080"

        console.print("[cyan][*] Enumerando portas e coletando banners...[/cyan]")
        host_details_for_report = []
        with open(output_file, "w", encoding="utf-8") as f_report:
            f_report.write(f"# Varredura de Rede Detalhada para: {target} em {time.ctime(start_time)}\n")

        nmap_scan_type = "-sS" if os.geteuid() == 0 else "-sT"

        for host in track(active_hosts_ips, description="Varrendo hosts e banners"):
            current_host_banner_infos, open_ports_nmap = [], []
            nmap_base_cmd_tcp = ["sudo"] if os.geteuid() == 0 and nmap_scan_type == "-sS" else []
            if nmap_base_cmd_tcp or nmap_scan_type == "-sT":
                nmap_base_cmd_tcp.append("nmap")
                tcp_cmd = nmap_base_cmd_tcp + [nmap_scan_type, "-T4", "--max-retries", "1", "--host-timeout", "3m",
                                               "-p", common_tcp_ports, host, "-oX", "-"]
                tcp_res = subprocess.run(tcp_cmd, capture_output=True, text=True, check=False)
                if tcp_res.stderr and "Failed to resolve" not in tcp_res.stderr:
                    console.print(f"[yellow][!] Nmap TCP ({host}): {tcp_res.stderr.strip()[:100]}[/yellow]", highlight=False)
                open_ports_nmap.extend(parse_nmap_xml_output(tcp_res.stdout))

            if os.geteuid() == 0:
                udp_nmap_base_cmd = ["sudo", "nmap"]
                udp_cmd = udp_nmap_base_cmd + ["-sU", "-T4", "--max-retries", "0", "--host-timeout", "5m", "-F",
                                               "--max-scan-delay", "20ms", host, "-oX", "-"]
                udp_res = subprocess.run(udp_cmd, capture_output=True, text=True, check=False)
                if udp_res.stderr and "Failed to resolve" not in udp_res.stderr:
                    console.print(f"[yellow][!] Nmap UDP ({host}): {udp_res.stderr.strip()[:100]}[/yellow]", highlight=False)
                open_ports_nmap.extend(parse_nmap_xml_output(udp_res.stdout))
            else:
                console.print(f"[yellow][!] Scan UDP para {host} pulado (requer root).[/yellow]", highlight=False)

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

        table_width = console.width - 4 if console.width > 80 else 80
        table = Table(title=f"Hosts Ativos e Serviços ({target})", show_lines=True, width=min(table_width, 140))
        table.add_column("IP", style="cyan", width=int(table_width * 0.15), overflow="fold")
        table.add_column("Porta/Proto", style="magenta", width=int(table_width * 0.15), overflow="fold")
        table.add_column("Serviço (Banner/Status/Info)", style="green", width=int(table_width * 0.70), overflow="fold")

        if not host_details_for_report:
            console.print(f"[yellow][!] Nenhum detalhe de host/porta para exibir.[/yellow]")
        for detail_entry in host_details_for_report:
            host_ip, ports_info_list = detail_entry["host"], detail_entry["ports_info"]
            if ports_info_list == ["Nenhuma porta aberta com banner detectada ou Nmap falhou em obter portas."]:
                table.add_row(host_ip, "-", ports_info_list[0])
            else:
                first_port_for_this_host = True
                for port_info_line in ports_info_list:
                    parts = port_info_line.split(": ", 1)
                    port_proto_display, banner_text_display = parts[0], parts[1] if len(parts) > 1 else "N/A"
                    if first_port_for_this_host:
                        table.add_row(host_ip, port_proto_display,
                                      banner_text_display)
                        first_port_for_this_host = False
                    else:
                        table.add_row("", port_proto_display, banner_text_display)
        console.print(table)
        end_time = time.time()
        console.print(f"[green][+] Varredura inicial concluída em {end_time - start_time:.2f} segundos.[/green]")
        console.print(
            f"[green][+] Total de hosts ativos processados na varredura inicial: {len(active_hosts_ips)}[/green]")
        console.print(f"[green][+] Resultados detalhados da varredura inicial salvos em: {output_file}[/green]")
        return active_hosts_ips
    except KeyboardInterrupt:
        console.print("[yellow][!] Varredura interrompida.[/yellow]")
        return []
    except Exception as e:
        console.print(f"[red][!] Erro inesperado no discover_hosts: {e}[/red]")
        import traceback
        traceback.print_exc()
        return []

def run_enhanced_version_detection(structured_initial_data):
    console.print("\n[cyan][*] Iniciando fase de detecção de versão aprimorada (-sV)...[/cyan]")
    for host_info in track(structured_initial_data, description="Aprimorando versões Nmap -sV..."):
        host_ip = host_info["host"]
        if not isinstance(host_info["services"], list):
            continue
        for service in host_info["services"]:
            port, protocol = service["port"], service["protocol"]
            service_name_upper = service.get("service_name", "").upper()
            details_upper = service.get("details", "").upper()
            needs_sv_scan, nmap_sv_scripts = False, []

            if protocol == "tcp" and (port in ["139", "445"] or "SMB" in service_name_upper):
                needs_sv_scan = True
                nmap_sv_scripts.extend(["smb-os-discovery", "smb-protocols", "smb-security-mode"])
            elif protocol == "tcp" and not service.get("version") and \
                    any(indicator in details_upper for indicator in
                        ["GENERIC TCP", "TIMEOUT", "NO IMMEDIATE BANNER", "NO BANNER"]) and \
                    not ("ALERTA DE SEGURANÇA" in details_upper or "INFO SEGURANÇA" in details_upper):
                needs_sv_scan = True

            if needs_sv_scan:
                console.print(f"  [blue]Executando Nmap -sV para {host_ip}:{port}/{protocol}[/blue]", highlight=False)
                nmap_command = []

                if os.geteuid() != 0 and not ('--no-root-check' in sys.argv or os.environ.get("ALLOW_NO_ROOT") == "1"):
                    console.print(
                        f"    [yellow]Aviso: -sV para {host_ip}:{port} pode ser limitado sem root e pode falhar.[/yellow]",
                        highlight=False)

                nmap_command.extend(["nmap", "-sV", "-Pn", "-p", f"T:{port}"])
                if nmap_sv_scripts:
                    nmap_command.extend(["--script", ",".join(nmap_sv_scripts)])
                nmap_command.extend([host_ip, "-oX", "-"])
                try:
                    sv_result = subprocess.run(nmap_command, capture_output=True, text=True, check=False, timeout=180)
                    if sv_result.returncode == 0 and sv_result.stdout:
                        sv_details = parse_nmap_sv_xml_details(sv_result.stdout)
                        if sv_details and not sv_details.get("error"):
                            service["nmap_sv_info"] = sv_details
                            new_product, new_version, new_extrainfo = sv_details.get("product"), sv_details.get(
                                "version"), sv_details.get("extrainfo")
                            updated_details_parts = []
                            if new_product:
                                updated_details_parts.append(new_product)
                            if new_version:
                                updated_details_parts.append(f"(Versão: {new_version})")
                                service["version"] = new_version
                            if new_extrainfo:
                                updated_details_parts.append(f"({new_extrainfo})")
                            if updated_details_parts:
                                original_details_for_sv_append = service['details'].split(". INFO NMAP -sV:")[0]
                                service[
                                    "details"] = f"{original_details_for_sv_append}. INFO NMAP -sV: {' '.join(updated_details_parts)}"
                            console.print(f"    [green]Versão aprimorada para {host_ip}:{port} obtida.[/green]",
                                          highlight=False)
                        elif sv_details.get("error"):
                            service["nmap_sv_info"] = {"error": f"Nmap -sV parsing: {sv_details.get('error')}"}
                        else:
                            service["nmap_sv_info"] = {"status": "Sem info detalhada do -sV."}
                    elif sv_result.stderr:
                        service["nmap_sv_info"] = {"error": f"Nmap -sV erro execução: {sv_result.stderr.strip()[:100]}"}
                except subprocess.TimeoutExpired:
                    service["nmap_sv_info"] = {"error": "Nmap -sV timeout"}
                except Exception as e:
                    service["nmap_sv_info"] = {"error": f"Nmap -sV exceção: {str(e)}"}
                time.sleep(0.5)
    console.print("[green][+] Fase de detecção de versão aprimorada (-sV) concluída.[/green]")

def run_fallback_nse_scans(structured_data):
    console.print("\n[cyan][*] Executando Nmap NSE específicos como fallback...[/cyan]")
    if not isinstance(structured_data, list):
        return

    NSE_FALLBACK_SCRIPTS = {
        "FTP": ["ftp-anon", "ftp-vuln-*"],
        "SSH": ["ssh-auth-methods", "ssh2-enum-algos", "ssh-hostkey"],
        "HTTP": ["http-enum", "http-title", "http-headers", "http-vuln-*"],
        "SMB": ["smb-os-discovery", "smb-protocols", "smb-security-mode", "smb-vuln-*", "smb-enum-shares",
                "smb-enum-users"],
        "MYSQL": ["mysql-empty-password", "mysql-info", "mysql-vuln-*"],
        "VNC": ["vnc-info", "vnc-brute"],
        "POSTGRESQL": ["pgsql-brute"]
    }
    for host_info in track(structured_data, description="Executando NSE fallback..."):
        host_ip = host_info["host"]
        if not isinstance(host_info.get("services"), list):
            continue
        for service in host_info["services"]:
            run_nse_for_this_service = False
            if service.get("protocol") == "tcp" and service.get("service_name"):
                if not service.get("vulnerabilities") or \
                        (service.get("vulnerabilities") and len(
                            service.get("vulnerabilities")) == 1 and "Intervalo de versões detectado" in
                         service.get("vulnerabilities")[0].get("info", "")):
                    run_nse_for_this_service = True
                elif "SMB" in service.get("service_name", "").upper():
                    run_nse_for_this_service = True

            if run_nse_for_this_service:
                service_name_key = service.get("service_name", "").upper()
                scripts_to_run = []
                for key_service_map, nse_scripts_list in NSE_FALLBACK_SCRIPTS.items():
                    if key_service_map in service_name_key:
                        scripts_to_run.extend(nse_scripts_list)
                scripts_to_run = sorted(list(set(scripts_to_run)))

                if scripts_to_run:
                    port = service["port"]
                    console.print(
                        f"  [blue]Executando NSE fallback para {service.get('service_name')} em {host_ip}:{port} (Scripts: {','.join(scripts_to_run)})[/blue]",
                        highlight=False)
                    nmap_command = []
                    if os.geteuid() != 0 and not (
                            '--no-root-check' in sys.argv or os.environ.get("ALLOW_NO_ROOT") == "1"):
                        console.print(
                            f"    [yellow]Aviso: Scan NSE para {host_ip}:{port} pode ser limitado sem root.[/yellow]",
                            highlight=False)

                    nmap_command.extend(["nmap", "-sV", "-Pn", "-p", f"T:{port}"])
                    nmap_command.extend(["--script", ",".join(scripts_to_run)])
                    nmap_command.extend(["--script-timeout", "5m"])
                    nmap_command.extend([host_ip, "-oX", "-"])
                    try:
                        nse_result_proc = subprocess.run(nmap_command, capture_output=True, text=True, check=False,
                                                         timeout=600)
                        if nse_result_proc.returncode == 0 and nse_result_proc.stdout:
                            nse_scan_details = parse_nmap_sv_xml_details(nse_result_proc.stdout)
                            if nse_scan_details and not nse_scan_details.get("error"):
                                if "nse_fallback_info" not in service:
                                    service["nse_fallback_info"] = {}
                                if nse_scan_details.get("script_outputs"):
                                    parsed_script_outputs = {}
                                    for script_id, output_text in nse_scan_details["script_outputs"].items():
                                        if script_id == "ssh-auth-methods" and "Supported authentication methods:" in output_text:
                                            methods = [m.strip() for m in output_text.splitlines()[1:] if m.strip()]
                                            parsed_script_outputs[script_id] = {"supported_methods": methods}
                                        elif script_id == "ssh2-enum-algos":
                                            algos_data = {}
                                            current_algo_type = None
                                            for line in output_text.splitlines():
                                                line_strip = line.strip()
                                                if ":" in line_strip and not line_strip.startswith("  "):
                                                    current_algo_type = line_strip.split(":")[0].replace("_algorithms",
                                                                                                         "").replace(
                                                        "server_host_key", "host_key").strip()
                                                    algos_data[current_algo_type] = []
                                                elif current_algo_type and line_strip:
                                                    algos_data[current_algo_type].append(
                                                        line_strip.split("(")[0].strip())
                                            parsed_script_outputs[script_id] = algos_data
                                        else:
                                            parsed_script_outputs[script_id] = output_text
                                    service["nse_fallback_info"]["script_outputs"] = parsed_script_outputs
                                    console.print(
                                        f"    [green]Resultados NSE para {host_ip}:{port} obtidos e parseados.[/green]",
                                        highlight=False)
                                else:
                                    service["nse_fallback_info"]["status"] = "Nenhum output de script NSE relevante."
                            elif nse_scan_details.get("error"):
                                service["nse_fallback_info"] = {
                                    "error": f"Parse NSE XML: {nse_scan_details.get('error')}"}
                        elif nse_result_proc.stderr:
                            service["nse_fallback_info"] = {
                                "error": f"Execução NSE: {nse_result_proc.stderr.strip()[:100]}"}
                    except subprocess.TimeoutExpired:
                        service["nse_fallback_info"] = {"error": "Nmap NSE timeout"}
                    except Exception as e:
                        service["nse_fallback_info"] = {"error": f"Exceção NSE: {str(e)}"}
                    time.sleep(1)
    console.print("[green][+] Fase de Nmap NSE fallback concluída.[/green]")
