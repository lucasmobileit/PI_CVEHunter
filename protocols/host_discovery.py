import os
import subprocess

def discover_hosts(network, output_file="hosts_ativos.txt", method="nmap"):
    active_hosts = []

    if method == "nmap":
        # Usando nmap para descoberta rápida
        print(f"[*] Iniciando descoberta de hosts com Nmap em {network}...")
        command = f"nmap -sn -PR {network} -oG - | awk '/Up/{{print $2}}' > {output_file}"
        os.system(command)

    elif method == "scapy":
        # Descoberta com scapy (ARP ping)
        from scapy.all import ARP, Ether, srp
        print(f"[*] Iniciando descoberta de hosts com Scapy em {network}...")
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
        answered, _ = srp(arp_request, timeout=2, verbose=0)

        with open(output_file, "w") as f:
            for sent, received in answered:
                active_hosts.append(received.psrc)
                f.write(f"{received.psrc}\\n")

    # Carrega os hosts ativos para integração com enumeração
    with open(output_file, "r") as f:
        active_hosts = [line.strip() for line in f.readlines()]

    print(f"[+] Hosts ativos descobertos: {len(active_hosts)}")
    return active_hosts
