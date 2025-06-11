import requests
from rich.console import Console
from rich.progress import track
import re

console = Console()
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_DELAY_NO_KEY = 7

def get_severity_from_cvss_v2(score):
    if not isinstance(score, (int, float)):
        return "N/A"
    score = float(score)
    if score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"

def normalize_version(version_str):
    """Normaliza strings de versão, extraindo a última versão de intervalos."""
    if not version_str:
        return None
    # Trata intervalos como '8.3.0 - 8.3.7'
    version_match = re.search(r'(\d+\.\d+\.\d+)(?:\s*-\s*(\d+\.\d+\.\d+))?', version_str)
    if version_match:
        # Retorna a última versão do intervalo, ou a única versão encontrada
        return version_match.group(2) if version_match.group(2) else version_match.group(1)
    # Retorna a versão se for um formato válido (e.g., '8.3.7')
    if re.match(r'^\d+\.\d+\.\d+(?:[a-zA-Z0-9\.\-]*)$', version_str):
        return version_str
    return None

def generate_heuristic_cpe(product_name, version_str):
    if not product_name:
        return None
    product_lower = product_name.lower().strip()
    version_clean = normalize_version(version_str) if version_str else None
    cpe_map = {
        "openssh": f"cpe:2.3:a:openbsd:openssh:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "ssh": f"cpe:2.3:a:openbsd:openssh:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "apache http server": f"cpe:2.3:a:apache:http_server:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "apache": f"cpe:2.3:a:apache:http_server:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "httpd": f"cpe:2.3:a:apache:http_server:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "http": f"cpe:2.3:a:apache:http_server:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "apache httpd": f"cpe:2.3:a:apache:http_server:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "apache2": f"cpe:2.3:a:apache:http_server:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "vsftpd": f"cpe:2.3:a:vsftpd_project:vsftpd:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "mysql": f"cpe:2.3:a:mysql:mysql:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "samba smbd": f"cpe:2.3:a:samba:samba:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "samba": f"cpe:2.3:a:samba:samba:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "postgresql db": f"cpe:2.3:a:postgresql:postgresql:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
        "postgresql": f"cpe:2.3:a:postgresql:postgresql:{version_clean or '*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}:{'*'}",
    }
    for key, cpe_format_string in cpe_map.items():
        if key in product_lower:
            console.print(f"[debug] CPE gerado para {product_name} {version_str}: {cpe_format_string}")
            return cpe_format_string
    console.print(f"[yellow]Nenhum CPE mapeado para {product_name}[/yellow]")
    return None

def query_nvd_for_vulnerabilities(product_name, version_str, api_key=None):
    vulnerabilities = []
    product_lower = product_name.lower().strip()
    heuristic_cpe = generate_heuristic_cpe(product_name, version_str)
    
    # Busca por CPE
    if heuristic_cpe:
        try:
            params = {"cpeName": heuristic_cpe, "resultsPerPage": 10}
            headers = {"apiKey": api_key} if api_key else {}
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                description = cve_data.get("descriptions", [{}])[0].get("value", "N/A")
                
                # Extrair métricas
                metrics = cve_data.get("metrics", {})
                console.print(f"[debug] Métricas disponíveis para {cve_id}: {metrics.keys()}")
                
                # Inicializar valores padrão
                cvss_score = None
                severity = "N/A"
                
                # Tenta CVSS 3.1 ou 3.0
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or \
                           metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                if cvss_data:
                    cvss_score = cvss_data.get("baseScore", None)
                    severity = cvss_data.get("baseSeverity", "N/A")
                
                # Fallback para CVSS 2.0
                if severity == "N/A" and metrics.get("cvssMetricV20"):
                    cvss_v2_data = metrics.get("cvssMetricV20", [{}])[0].get("cvssData", {})
                    cvss_score = cvss_v2_data.get("baseScore", None)
                    severity = get_severity_from_cvss_v2(cvss_score)
                
                # Logar se não houver métricas
                if cvss_score is None:
                    console.print(f"[yellow]Nenhuma métrica CVSS encontrada para {cve_id}[/yellow]")
                
                references = [ref.get("url") for ref in cve_data.get("references", [])]
                vulnerabilities.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": references,
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": "NVD"
                })
            console.print(f"[green]NVD: {len(vulnerabilities)} CVEs encontrados para '{heuristic_cpe}'[/green]")
        except requests.exceptions.HTTPError as e:
            console.print(f"[red]Erro na API NVD com CPE {heuristic_cpe}: {e}[/red]")
    
    # Fallback: Busca por palavras-chave
    if not vulnerabilities and product_name:
        try:
            version_clean = normalize_version(version_str) if version_str else '*'
            keyword = f"{product_name} {version_clean}" if version_clean != '*' else product_name
            params = {"keywordSearch": keyword, "resultsPerPage": 10}
            headers = {"apiKey": api_key} if api_key else {}
            response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            for vuln in data.get("vulnerabilities", []):
                cve_data = vuln.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                description = cve_data.get("descriptions", [{}])[0].get("value", "N/A")
                
                # Extrair métricas
                metrics = cve_data.get("metrics", {})
                console.print(f"[debug] Métricas disponíveis para {cve_id}: {metrics.keys()}")
                
                # Inicializar valores padrão
                cvss_score = None
                severity = "N/A"
                
                # Tenta CVSS 3.1 ou 3.0
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) or \
                           metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                if cvss_data:
                    cvss_score = cvss_data.get("baseScore", None)
                    severity = cvss_data.get("baseSeverity", "N/A")
                
                # Fallback para CVSS 2.0
                if severity == "N/A" and metrics.get("cvssMetricV20"):
                    cvss_v2_data = metrics.get("cvssMetricV20", [{}])[0].get("cvssData", {})
                    cvss_score = cvss_v2_data.get("baseScore", None)
                    severity = get_severity_from_cvss_v2(cvss_score)
                
                # Logar se não houver métricas
                if cvss_score is None:
                    console.print(f"[yellow]Nenhuma métrica CVSS encontrada para {cve_id}[/yellow]")
                
                references = [ref.get("url") for ref in cve_data.get("references", [])]
                vulnerabilities.append({
                    "cve_id": cve_id,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": references,
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "source": "NVD (Keyword)"
                })
            console.print(f"[green]NVD: {len(vulnerabilities)} CVEs encontrados com keyword '{keyword}'[/green]")
        except requests.exceptions.HTTPError as e:
            console.print(f"[red]Erro na API NVD com keyword {keyword}: {e}[/red]")
    
    return vulnerabilities

def add_nvd_vulnerability_info(structured_data, nvd_api_key=None):
    console.print("\n[cyan][*] Consultando NVD para vulnerabilidades...[/cyan]")
    for host_info in track(structured_data, description="Consultando APIs..."):
        if not isinstance(host_info.get("services"), list):
            continue
        for service in host_info["services"]:
            version = service.get("version")
            product_name = service.get("nmap_sv_info", {}).get("product") or service.get("service_name")
            service["vulnerabilities"] = []
            if product_name:
                service["vulnerabilities"] = query_nvd_for_vulnerabilities(product_name, version, nvd_api_key)
                if not service["vulnerabilities"]:
                    service["vulnerability_query_status"] = f"Nenhuma vulnerabilidade encontrada para {product_name} {version or '*'}"
    console.print("[green][+] Consultas à API NVD concluídas.[/green]")
