from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP, ICMP
import random
import logging

# Configuração de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Timeout padrão
DEFAULT_TIMEOUT = 2

def validate_inputs(host, port):
    """
    Valida os parâmetros de entrada para as funções de enumeração.
    """
    if not isinstance(host, str):
        raise ValueError("Host must be a string.")
    if not (isinstance(port, int) and 0 <= port <= 65535):
        raise ValueError("Port must be an integer between 0 and 65535.")

def create_packet(host, port, protocol="TCP"):
    """
    Cria pacotes TCP ou UDP para envio.
    """
    if protocol == "TCP":
        return IP(dst=host) / TCP(dport=port, flags="S", seq=random.randint(0, 4294967295))
    elif protocol == "UDP":
        return IP(dst=host) / UDP(dport=port) / b"\\x00" * 8
    else:
        raise ValueError("Unsupported protocol. Use 'TCP' or 'UDP'.")

def active_enum_tcp(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Realiza a enumeração ativa de uma porta TCP em um host.

    Args:
        host (str): Endereço IP ou hostname do alvo.
        port (int): Porta TCP a ser verificada.
        timeout (int, opcional): Tempo limite para resposta. Padrão é 2 segundos.

    Returns:
        str: Resultado da enumeração (aberta, fechada ou filtrada).
    """
    try:
        validate_inputs(host, port)
        logging.info(f"Scanning TCP port {port} on {host}")

        # Criação do pacote SYN
        syn_pkt = create_packet(host, port, protocol="TCP")
        
        # Envio e recepção do pacote
        response = sr1(syn_pkt, timeout=timeout, verbose=0)
        
        # Verificando resposta SYN-ACK (flags=0x12) ou RST (flags=0x14)
        if response and response.haslayer(TCP):
            tcp_flags = response.getlayer(TCP).flags
            if tcp_flags == 0x12:  # SYN-ACK
                return f"Port {port} open on {host} (TCP)"
            elif tcp_flags == 0x14:  # RST
                return f"Port {port} closed on {host} (TCP)"
        
        return f"Port {port} filtered or no response on {host} (TCP)"
    
    except Exception as e:
        logging.error(f"Error scanning {host}:{port} (TCP) - {type(e).__name__}: {str(e)}")
        return f"Error scanning {host}:{port} - {str(e)}"

def active_enum_udp(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Realiza a enumeração ativa de uma porta UDP em um host.

    Args:
        host (str): Endereço IP ou hostname do alvo.
        port (int): Porta UDP a ser verificada.
        timeout (int, opcional): Tempo limite para resposta. Padrão é 2 segundos.

    Returns:
        str: Resultado da enumeração (aberta, fechada ou filtrada).
    """
    try:
        validate_inputs(host, port)
        logging.info(f"Scanning UDP port {port} on {host}")

        # Criação do pacote UDP com carga mínima
        udp_pkt = create_packet(host, port, protocol="UDP")
        
        # Envio e recepção do pacote
        response = sr1(udp_pkt, timeout=timeout, verbose=0)
        
        # Verificando resposta ICMP Port Unreachable (ICMP Type 3, Code 3)
        if response and response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code
            if icmp_type == 3 and icmp_code == 3:
                return f"Port {port} closed on {host} (UDP)"
        
        # Se não houve ICMP, assume porta aberta ou filtrada
        return f"Port {port} open or filtered on {host} (UDP)"
    
    except Exception as e:
        logging.error(f"Error scanning {host}:{port} (UDP) - {type(e).__name__}: {str(e)}")
        return f"Error scanning {host}:{port} - {str(e)}"
