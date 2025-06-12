# CVE Hunter (Projeto acadêmico)

Scanner de rede avançado com:
- Descoberta de hosts via Nmap
- Coleta de banners (TCP/UDP) 
- Enriquecimento com Nmap -sV
- Consulta de vulnerabilidades via API da NVD com métricas CvssMetric2.0 até 3.1.
- Fallback NSE scripts (opcional pela opção via cli)
- Exportação em `.txt` e `.json`
- CLI interativa com Rich

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
```text
network_scanner/
├── scanner/
│   ├── main.py
│   ├── nmap_scanning.py
│   ├── banner_grabbing.py
│   ├── save_to_mongodb.py
│   ├── parsing.py
│   ├── nvd_queries.py
│   ├── utils.py
│   ├── report.html

```

## Análise dos dados coletados:
- Utilizamos a conexão do Pymongo para o banco de dados, e esses dados coletados apresentamos no PowerBI em forma de relátorio.
- Como fallback fazemos a conexão do json com um arquivo html para apresentação do relatório.

## 🔐 Requisitos:
- Python 3.6+
- Bibliotecas: `pip install rich requests pymongo json`
- Nmap: `sudo apt install nmap`
- Opcional: chave de API NVD (https://nvd.nist.gov/developers/request-an-api-key)
