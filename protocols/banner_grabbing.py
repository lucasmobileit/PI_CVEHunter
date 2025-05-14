import socket
import logging

# Configuração de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Timeout padrão
DEFAULT_TIMEOUT = 2

# Comandos específicos para portas
PORT_COMMANDS = {
    21: b"HELO\r\n",  # FTP
    25: b"HELO\r\n",  # SMTP
    110: b"HELO\r\n",  # POP3
    143: b"HELO\r\n",  # IMAP
    993: b"HELO\r\n",  # IMAPS
    995: b"HELO\r\n",  # POP3S
    80: b"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n",  # HTTP
    443: b"HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n",  # HTTPS
    123: b"\x1b" + b"\0" * 47,  # NTP
    53: b"\xAA\xAA\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01",  # DNS
}

def validate_inputs(host, port):
    """
    Valida os parâmetros de entrada para a função de banner grabbing.
    """
    if not isinstance(host, str):
        raise ValueError("Host must be a string.")
    if not (isinstance(port, int) and 0 <= port <= 65535):
        raise ValueError("Port must be an integer between 0 and 65535.")

def grab_banner(host, port, timeout=DEFAULT_TIMEOUT):
    """
    Realiza o banner grabbing de um serviço em uma porta específica.

    Args:
        host (str): Endereço IP ou hostname do alvo.
        port (int): Porta do serviço a ser verificado.
        timeout (int, opcional): Tempo limite para a conexão. Padrão é 2 segundos.

    Returns:
        str: Banner recebido ou mensagem de erro.
    """
    try:
        validate_inputs(host, port)
        logging.info(f"Attempting to grab banner from {host}:{port}")

        with socket.create_connection((host, port), timeout=timeout) as sock:
            command = PORT_COMMANDS.get(port)
            if command:
                if b"{host}" in command:
                    command = command.replace(b"{host}", bytes(host, "utf-8"))
                sock.send(command)
            else:
                logging.warning(f"No predefined command for port {port}. Sending no data.")

            banner = sock.recv(1024).decode().strip()
            logging.info(f"Banner received from {host}:{port}")
            return f"Banner from {host}:{port} -> {banner}"
    except Exception as e:
        logging.error(f"Error grabbing banner from {host}:{port} - {type(e).__name__}: {str(e)}")
        return f"Error grabbing banner from {host}:{port} - {str(e)}"
