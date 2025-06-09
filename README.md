# Network Scanner

Scanner de rede avançado com:

- Descoberta de hosts via Nmap
- Coleta de banners (TCP/UDP)
- Enriquecimento com Nmap -sV
- Consulta de vulnerabilidades via API da NVD
- Fallback NSE scripts (opcional)
- Exportação em `.txt` e `.json`
- CLI interativa com Rich

---

## 🚀 Instalação

```bash
git clone https://github.com/lucasmobileit/network-scanner.git [!]
cd network-scanner
pip install -r requirements.txt
pip install -e .
```
---

## Uso da CLI

```python
network-scanner -t 192.168.0.0/24 --enable-nse-fallback --nvd-api-key SEU_TOKEN
```

## Principais opções:
| Parâmetro               | Descrição                                   |
| ----------------------- | ------------------------------------------- |
| `-t` / `--target`       | IP, faixa CIDR ou hostname                  |
| `-o` / `--output-text`  | Arquivo `.txt` com resultado do banner grab |
| `-jo` / `--json-output` | Arquivo JSON estruturado                    |
| `--nvd-api-key`         | Token da NVD para evitar rate-limit         |
| `--enable-nse-fallback` | Executa scripts NSE em serviços relevantes  |
| `--no-root-check`       | Permite execução sem root (usa -sT)         |


## Estrutura modular:
network_scanner/
├── scanner/
│   ├── cli.py
│   ├── main.py
│   ├── discovery.py
│   ├── parser.py
│   ├── enrichment.py
│   ├── vulnerabilities.py
│   ├── utils.py
│   └── banner_handlers/
│       ├── tcp.py
│       └── udp.py
├── tests/
│   ├── test_parser.py
│   ├── test_utils.py
│   └── test_vulnerabilities.py


## 🔐 Requisitos:
- Python 3.7+
- Permissões de root (para -sS, -sU e NSE completo)
