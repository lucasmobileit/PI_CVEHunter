import socket
import ssl
import os
from rich.console import Console

console = Console()

def _grab_banner_generic_tcp(sock, host, port):
    sock.settimeout(2)
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    return f"Generic TCP: {banner[:60]}" if banner else "Generic TCP: No immediate banner"

def _grab_ftp_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    return f"FTP: {banner[:60]}" if banner else "FTP: No banner"

def _grab_ssh_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    return f"SSH: {banner[:60]}" if banner else "SSH: No banner"

def _grab_telnet_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if banner and not banner.upper().startswith("TELNET:"):
        return f"Telnet: {banner[:60]}"
    elif not banner:
        return "Telnet: No banner"
    return banner[:70]

def _grab_smtp_banner(sock, host, port):
    try:
        sock.settimeout(2)
        initial_banner_bytes = sock.recv(1024)
        initial_banner = initial_banner_bytes.decode('utf-8', errors='ignore').strip()
        sock.settimeout(3)
        final_banner_str = initial_banner
        if "220" in initial_banner:
            try:
                sock.sendall(b"EHLO example.com\r\n")
                ehlo_banner_bytes = sock.recv(1024)
                ehlo_banner = ehlo_banner_bytes.decode('utf-8', errors='ignore').strip()
                if ehlo_banner:
                    first_initial = initial_banner.splitlines()[0] if initial_banner.splitlines() else initial_banner
                    first_ehlo = ehlo_banner.splitlines()[0] if ehlo_banner.splitlines() else ehlo_banner
                    final_banner_str = f"{first_initial}; {first_ehlo}"
            except socket.timeout:
                pass
            except Exception:
                pass
        if not final_banner_str:
            return "SMTP: No banner"
        if not final_banner_str.upper().startswith("SMTP:"):
            return f"SMTP: {final_banner_str[:60]}"
        return final_banner_str[:70]
    except socket.timeout:
        return "SMTP: Timeout"
    except Exception as e:
        return f"SMTP: Error ({str(e)[:45]})"

def _grab_http_banner_logic(sock, host, port_num, service_name="HTTP"):
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: IT-Scanner\r\nConnection: close\r\n\r\n"
    try:
        sock.send(request.encode('utf-8'))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        for line in banner.splitlines():
            if line.lower().startswith('server:'):
                return f"{service_name}: {line.split(':', 1)[1].strip()[:60]}"
        return f"{service_name}: No server banner (Banner: {banner[:50]})" if banner else f"{service_name}: No server banner"
    except Exception as e:
        return f"{service_name}: Error grabbing banner ({str(e)[:40]})"

def _grab_http_banner(sock, host, port):
    return _grab_http_banner_logic(sock, host, port, "HTTP")

def _grab_http_alt_banner(sock, host, port):
    return _grab_http_banner_logic(sock, host, port, "HTTP (Alt)")

def _grab_pop3_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if not banner.upper().startswith("POP3:"):
        return f"POP3: {banner[:60]}" if banner else "POP3: No banner"
    return banner[:70]

def _grab_rpc_banner(sock, host, port):
    return "RPC: Service detected"

def _grab_imap_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if not banner.upper().startswith("IMAP:"):
        return f"IMAP: {banner[:60]}" if banner else "IMAP: No banner"
    return banner[:70]

def _grab_https_banner(sock, host, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with context.wrap_socket(sock, server_hostname=host, do_handshake_on_connect=False) as ssock:
            ssock.do_handshake()
            cert = ssock.getpeercert()
            if cert:
                subject = dict(x[0] for x in cert['subject'])
                common_name = subject.get('commonName', 'N/A')
                return f"HTTPS: CommonName={common_name[:55]}"
            else:
                return "HTTPS: Connection successful, no peer certificate"
    except ssl.SSLError as ssl_e:
        return f"HTTPS: TLS Error ({str(ssl_e)[:55]})"
    except Exception as e:
        return f"HTTPS: Connection or Handshake Error ({str(e)[:40]})"

def _grab_smb_banner(sock, host, port):
    smb_packet = bytes.fromhex("0000002fff534d42720000000000000000000000000000000000000000000000")
    try:
        sock.send(smb_packet)
        banner = sock.recv(1024).hex()
        return f"SMB: Negotiated (hex: {banner[:55]})" if banner else "SMB: No response"
    except Exception as e:
        return f"SMB: Error ({str(e)[:45]})"

def _grab_mssql_banner(sock, host, port):
    banner = sock.recv(1024).hex()
    return f"MSSQL: Detected (hex: {banner[:55]})" if banner else "MSSQL: No response"

def _grab_mysql_banner(sock, host, port):
    banner_content = sock.recv(1024)
    try:
        if len(banner_content) > 5:
            null_byte_index = banner_content.find(b'\x00', 5)
            if null_byte_index != -1:
                version_info = banner_content[5:null_byte_index].decode('utf-8', errors='ignore')
                return f"MySQL: {version_info[:60]}"
        return f"MySQL: Detected (hex: {banner_content.hex()[:55]})" if banner_content else "MySQL: No banner"
    except Exception:
        return f"MySQL: Detected (raw hex: {banner_content.hex()[:50]})" if banner_content else "MySQL: No banner"

def _grab_rdp_banner(sock, host, port):
    return "RDP: Service detected"

def _grab_postgresql_banner(sock, host, port):
    try:
        banner_bytes = sock.recv(1024)
        if banner_bytes:
            try:
                banner_text = banner_bytes.decode('utf-8', errors='replace').strip()
                if banner_text and (
                        banner_text.startswith('E') or banner_text.startswith('R') or banner_text.startswith('N')):
                    return f"PostgreSQL: Initial response detected ('{banner_text[0]}')"
                if banner_text:
                    return f"PostgreSQL: Response (text: {banner_text[:50]})"
                return f"PostgreSQL: Response (hex: {banner_bytes.hex()[:50]})"
            except UnicodeDecodeError:
                return f"PostgreSQL: Response (hex: {banner_bytes.hex()[:50]})"
        return "PostgreSQL: No immediate banner"
    except Exception:
        return "PostgreSQL: No immediate banner / Timeout"

def _grab_vnc_banner(sock, host, port):
    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
    if banner.startswith("RFB"):
        return f"VNC: {banner[:60]}"
    return f"VNC: Detected (banner: {banner[:55]})" if banner else "VNC: No banner"

def _grab_redis_banner(sock, host, port):
    sock.sendall(b"INFO\r\n")
    banner = sock.recv(4096).decode('utf-8', errors='ignore').strip()
    if banner.startswith("$") or banner.startswith("#"):
        first_line = banner.splitlines()[0] if banner.splitlines() else ""
        return f"Redis: INFO Response ({first_line[:55]})"
    return f"Redis: {banner[:60]}" if banner else "Redis: No banner"

def _grab_banner_generic_udp(sock, host, port):
    try:
        sock.sendto(b"\x00", (host, port))
        banner, _ = sock.recvfrom(1024)
        return f"Generic UDP: Response (hex: {banner.hex()[:50]})" if banner else "Generic UDP: No response to null byte"
    except socket.timeout:
        return "Generic UDP: Timeout on null byte probe"
    except Exception:
        return "Generic UDP: Service detected (no specific banner probe)"

def _grab_dns_banner_udp(sock, host, port):
    dns_packet = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")
    sock.sendto(dns_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    if banner and banner[:2] == dns_packet[:2]:
        return f"DNS: Valid response (hex: {banner.hex()[:50]})"
    return f"DNS: Response (hex: {banner.hex()[:50]})" if banner else "DNS: No response"

def _grab_dhcp_server_banner_udp(sock, host, port):
    return "DHCP Server: Detected (standard port)"

def _grab_dhcp_client_banner_udp(sock, host, port):
    return "DHCP Client: Detected (standard port)"

def _grab_tftp_banner_udp(sock, host, port):
    tftp_packet = b"\x00\x01" + b"testfile" + b"\x00" + b"octet" + b"\x00"
    sock.sendto(tftp_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    if banner and banner[:2] == b"\x00\x05":
        error_code = int.from_bytes(banner[2:4], 'big')
        return f"TFTP: Error packet (code {error_code}) (hex: {banner.hex()[:45]})"
    return f"TFTP: Response (hex: {banner.hex()[:50]})" if banner else "TFTP: No response"

def _grab_ntp_banner_udp(sock, host, port):
    ntp_packet = bytearray(48)
    ntp_packet[0] = 0b00100011
    sock.sendto(ntp_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    if banner and len(banner) == 48:
        return f"NTP: Valid response (hex: {banner.hex()[:50]})"
    return f"NTP: Response (hex: {banner.hex()[:50]})" if banner else "NTP: No response"

def _grab_netbios_ns_banner_udp(sock, host, port):
    nbns_query = bytes.fromhex(
        "00000010000100000000000020434b4141414141414141414141414141414141414141414141414141414141410000210001")
    sock.sendto(nbns_query, (host, port))
    banner, _ = sock.recvfrom(1024)
    return f"NetBIOS Name: Response (hex: {banner.hex()[:45]})" if banner else "NetBIOS Name: No response"

def _grab_netbios_dgm_banner_udp(sock, host, port):
    return "NetBIOS Datagram: Detected (standard port)"

def _grab_snmp_banner_udp(sock, host, port):
    snmp_packet = bytes.fromhex("302602010104067075626c6963a019020400000000020100020100300b300906052b0601020101010500")
    sock.sendto(snmp_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    try:
        if banner and banner[0] == 0x30:
            return f"SNMP: Response (hex: {banner.hex()[:50]})"
        decoded_banner = banner.decode('utf-8', errors='ignore').strip()
        return f"SNMP: {decoded_banner[:50]}" if decoded_banner else f"SNMP: Response (hex: {banner.hex()[:50]})"
    except Exception:
        return f"SNMP: Response (hex: {banner.hex()[:50]})" if banner else "SNMP: No response"

def _grab_snmp_trap_banner_udp(sock, host, port):
    return "SNMP Trap: Detected (standard port)"

def _grab_isakmp_banner_udp(sock, host, port):
    ike_packet = os.urandom(8) + b"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x2c" + \
                 b"\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x01"
    sock.sendto(ike_packet, (host, port))
    banner, _ = sock.recvfrom(1024)
    return f"ISAKMP/IKE: Response (hex: {banner.hex()[:50]})" if banner else "ISAKMP/IKE: No response"

def _grab_syslog_banner_udp(sock, host, port):
    return "Syslog: Detected (standard port, typically no banner)"

def _grab_ipsec_natt_banner_udp(sock, host, port):
    natt_keepalive = b"\x00\x00\x00\x00\xff"
    sock.sendto(natt_keepalive, (host, port))
    try:
        banner, _ = sock.recvfrom(1024)
        return f"IPSec NAT-T: Response (hex: {banner.hex()[:45]})" if banner else "IPSec NAT-T: No direct response"
    except socket.timeout:
        return "IPSec NAT-T: Detected (no response to keepalive)"

TCP_BANNER_HANDLERS = {
    21: _grab_ftp_banner, 22: _grab_ssh_banner, 23: _grab_telnet_banner, 25: _grab_smtp_banner,
    80: _grab_http_banner, 110: _grab_pop3_banner, 135: _grab_rpc_banner, 143: _grab_imap_banner,
    443: _grab_https_banner, 445: _grab_smb_banner, 1433: _grab_mssql_banner,
    3306: _grab_mysql_banner, 3389: _grab_rdp_banner, 5432: _grab_postgresql_banner,
    5900: _grab_vnc_banner, 6379: _grab_redis_banner, 8080: _grab_http_alt_banner
}

UDP_BANNER_HANDLERS = {
    53: _grab_dns_banner_udp, 67: _grab_dhcp_server_banner_udp, 68: _grab_dhcp_client_banner_udp,
    69: _grab_tftp_banner_udp, 123: _grab_ntp_banner_udp, 137: _grab_netbios_ns_banner_udp,
    138: _grab_netbios_dgm_banner_udp, 161: _grab_snmp_banner_udp, 162: _grab_snmp_trap_banner_udp,
    500: _grab_isakmp_banner_udp, 514: _grab_syslog_banner_udp, 4500: _grab_ipsec_natt_banner_udp
}

def grab_banner_tcp(host, port, timeout=3):
    banner_function = TCP_BANNER_HANDLERS.get(port, _grab_banner_generic_tcp)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return banner_function(sock, host, port)
    except socket.timeout:
        return "Timeout"
    except ConnectionRefusedError:
        return "Connection Refused"
    except Exception as e:
        return f"Error: {str(e)[:60]}"
    finally:
        if sock:
            sock.close()

def grab_banner_udp(host, port, timeout=3):
    banner_function = UDP_BANNER_HANDLERS.get(port, _grab_banner_generic_udp)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        return banner_function(sock, host, port)
    except socket.timeout:
        return "Timeout"
    except ConnectionRefusedError:
        return "Connection Refused (ICMP)"
    except Exception as e:
        return f"Error: {str(e)[:60]}"
    finally:
        if sock:
            sock.close()
