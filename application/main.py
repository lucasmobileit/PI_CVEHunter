import argparse
import os
import sys
from rich.console import Console
from nmap_scanning import discover_hosts
from parsing import parse_banner_scan_report_content
from nmap_scanning import run_enhanced_version_detection, run_fallback_nse_scans
from nvd_queries import add_nvd_vulnerability_info
from utils import validate_input
from save_to_mongodb import SaveMongo
import json

console = Console()

def main():
    parser = argparse.ArgumentParser(
        description="Scanner de rede avançado com análise de vulnerabilidades NVD e Nmap NSE.")
    parser.add_argument("-t", "--target", required=True, type=str, help="Alvo da varredura (IP, CIDR, hostname).")
    parser.add_argument("-o", "--output-text", type=str, default="scan_results.txt",
                        help="Arquivo de saída para o relatório de texto do scan de banner.")
    parser.add_argument("-jo", "--json-output", type=str,
                        help="Nome do arquivo para salvar o relatório JSON final (parseado e enriquecido).")
    parser.add_argument("--nvd-api-key", type=str, default=None,
                        help="Chave API para o NVD (opcional, para limites de taxa maiores).")
    parser.add_argument("--enable-nse-fallback", action="store_true",
                        help="Habilitar Nmap NSE fallback para serviços onde APIs não encontraram CVEs.")
    parser.add_argument("--no-root-check", action="store_true",
                        help="Permitir execução sem privilégios de root (Nmap usará -sT; funcionalidade de -sV e NSE pode ser limitada).")
    args = parser.parse_args()

    if args.no_root_check:
        os.environ["ALLOW_NO_ROOT"] = "1"
    elif os.geteuid() != 0:
        console.print(
            "[bold red][!] ERRO: Este script precisa de privilégios de root para executar varreduras Nmap -sS e -sU eficazmente.[/bold red]")
        console.print(
            "     Use 'sudo python seu_script.py ...' ou adicione '--no-root-check' para uma varredura limitada (Nmap usará -sT).")
        sys.exit(1)

    input_type = validate_input(args.target)
    if not input_type:
        sys.exit(1)

    # Fase 1: Descoberta de Hosts e Banner Grabbing Inicial
    active_hosts_scanned = discover_hosts(args.target, input_type, output_file=args.output_text)

    # Fase 2: Parseamento, Enriquecimento com -sV, Consulta ao NVD e Fallback NSE
    if os.path.exists(args.output_text):
        if active_hosts_scanned:
            console.print(f"\n[green][+] Hosts identificados na varredura inicial: {active_hosts_scanned}[/green]")

        console.print(f"\n[cyan][*] Parseando relatório de texto '{args.output_text}'...[/cyan]")
        try:
            with open(args.output_text, "r", encoding="utf-8") as f:
                report_content = f.read()
            report_lines = report_content.strip().splitlines()

            if not report_content.strip() or (
                    len(report_lines) <= 1 and report_lines[0].startswith("# Varredura de Rede Detalhada para:")):
                console.print(
                    f"[yellow][!] Relatório '{args.output_text}' está vazio ou contém apenas o cabeçalho. Sem dados para processamento adicional.[/yellow]")
            else:
                structured_data = parse_banner_scan_report_content(report_content)
                console.print("[green][+] Parseamento inicial do relatório concluído.[/green]")

                run_enhanced_version_detection(structured_data)

                add_nvd_vulnerability_info(structured_data, nvd_api_key=args.nvd_api_key)

                if args.enable_nse_fallback:
                    run_fallback_nse_scans(structured_data)

                json_file_name = args.json_output if args.json_output else f"{os.path.splitext(args.output_text)[0]}_final_report.json"
                with open(json_file_name, "w", encoding="utf-8") as json_f:
                    json.dump(structured_data, json_f, indent=2, ensure_ascii=False)
                console.print(
                    f"\n[bold green][+] Relatório final JSON (com Nmap -sV, NVD e NSE fallback) salvo em: '{json_file_name}'[/bold green]")

                # Save the JSON data to MongoDB
                console.print(f"\n[cyan][*] Salvando dados no MongoDB...[/cyan]")
                SaveMongo()

        except FileNotFoundError:
            console.print(f"[red][!] Relatório '{args.output_text}' não encontrado para processamento.[/red]")
        except Exception as e:
            console.print(f"[red][!] Erro durante o processamento do relatório '{args.output_text}': {e}[/red]")
            console.print_exception(show_locals=False)
    else:
        console.print(
            f"[yellow][!] Relatório '{args.output_text}' não foi gerado. Nenhum dado para processar.[/yellow]")
        if not active_hosts_scanned:
            console.print("[yellow][!] Nenhum host ativo encontrado na varredura inicial.[/yellow]")

if __name__ == "__main__":
    main()
