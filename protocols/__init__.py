from .active_enum import active_enum_tcp, active_enum_udp, validate_inputs, create_packet
from .banner_grabbing import grab_banner, PORT_COMMANDS
# O módulo correto de descoberta de hosts é `host_discovery`. O nome
# `host_discovery_module` não existe e fazia o import falhar ao usar
# o pacote via `from protocols import discover_hosts`.
from .host_discovery import discover_hosts
