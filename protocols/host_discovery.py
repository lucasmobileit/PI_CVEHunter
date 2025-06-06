import os
import subprocess


def _nmap_discovery(network, output_file):
    """Run an nmap discovery scan and save results to ``output_file``."""
    command = [
        "nmap",
        "-sn",
        "-PR",
        network,
        "-oG",
        "-",
    ]
    try:
        res = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        print("[!] Nmap não encontrado no sistema.")
        return

    if res.returncode != 0:
        print(f"[!] Erro ao executar nmap: {res.stderr.strip()}")
        return

    with open(output_file, "w") as f:
        for line in res.stdout.splitlines():
            if "Up" in line:
                parts = line.split()
                if len(parts) >= 2:
                    f.write(parts[1] + "\n")

def discover_hosts(network, output_file="hosts_ativos.txt", method="nmap"):
    active_hosts = []

    if method == "nmap":
        # Usando nmap para descoberta rápida
        print(f"[*] Iniciando descoberta de hosts com Nmap em {network}...")
        _nmap_discovery(network, output_file)

    elif method == "scapy":
        # Descoberta com scapy (ARP ping)
        from scapy.all import ARP, Ether, srp
        print(f"[*] Iniciando descoberta de hosts com Scapy em {network}...")
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(arp_request, timeout=2, verbose=0)

        with open(output_file, "w") as f:
            for _, received in answered:
                f.write(f"{received.psrc}\\n")

    else:
        print(f"[!] Método de descoberta {method} não suportado.")
        return []

    if not os.path.exists(output_file):
        print(f"[!] Arquivo de saída {output_file} não encontrado.")
        return []

    # Carrega os hosts ativos para integração com enumeração
    with open(output_file, "r") as f:
        active_hosts = [line.strip() for line in f if line.strip()]

    print(f"[+] Hosts ativos descobertos: {len(active_hosts)}")
    return active_hosts
