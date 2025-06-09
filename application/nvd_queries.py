import requests
import time
import re
from rich.console import Console
from rich.progress import track

console = Console()

NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_REQUEST_DELAY_NO_KEY = 7
NVD_REQUEST_DELAY_WITH_KEY = 1.2

def generate_heuristic_cpe(product_name, version_str):
    if not product_name or not version_str:
        return None
    product_lower = product_name.lower()
    version_clean = re.split(r'[-_ ]', version_str)[0]
    version_clean = re.sub(r'p\d+$', '', version_clean)

    cpe_map = {
        "openssh": f"cpe:2.3:a:openbsd:openssh:{version_clean}:*:*:*:*:*:*:*",
        "vsftpd": f"cpe:2.3:a:vsftpd_project:vsftpd:{version_clean}:*:*:*:*:*:*:*",
        "apache http server": f"cpe:2.3:a:apache:http_server:{version_clean}:*:*:*:*:*:*:*",
        "apache": f"cpe:2.3:a:apache:http_server:{version_clean}:*:*:*:*:*:*:*",
        "httpd": f"cpe:2.3:a:apache:http_server:{version_clean}:*:*:*:*:*:*:*",
        "mysql": f"cpe:2.3:a:mysql:mysql:{version_clean}:*:*:*:*:*:*:*",
        "samba smbd": f"cpe:2.3:a:samba:samba:{version_clean}:*:*:*:*:*:*:*",
        "samba": f"cpe:2.3:a:samba:samba:{version_clean}:*:*:*:*:*:*:*",
        "postgresql db": f"cpe:2.3:a:postgresql:postgresql:{version_clean}:*:*:*:*:*:*:*",
        "postgresql": f"cpe:2.3:a:postgresql:postgresql:{version_clean}:*:*:*:*:*:*:*",
    }
    for key, cpe_format_string in cpe_map.items():
        if key in product_lower:
            return cpe_format_string
    return None

def query_nvd_for_vulnerabilities(product_name, version_str, nvd_api_key=None):
    vulnerabilities_found = []
    if not product_name or not version_str:
        return vulnerabilities_found

    is_version_range = " - " in version_str or " to " in version_str.lower() or "through" in version_str.lower()
    if is_version_range:
        console.print(
            f"    [yellow]NVD: Intervalo de versão '{version_str}' para '{product_name}'. Consulta automática pulada. Verifique manualmente.[/yellow]",
            highlight=False)
        return [{"info": f"Intervalo de versões detectado: '{version_str}'. Recomenda-se consulta manual de CVEs."}]

    heuristic_cpe = generate_heuristic_cpe(product_name, version_str)

    params = {}
    search_type_log = ""
    if heuristic_cpe:
        params = {"cpeName": heuristic_cpe, "resultsPerPage": 10}
        search_type_log = f"CPE: {heuristic_cpe}"
    else:
        search_term = f"{product_name} {version_str}"
        params = {"keywordSearch": search_term, "resultsPerPage": 5}
        search_type_log = f"Keyword: {search_term}"

    headers = {}
    current_delay = NVD_REQUEST_DELAY_NO_KEY
    if nvd_api_key:
        headers['apiKey'] = nvd_api_key
        current_delay = NVD_REQUEST_DELAY_WITH_KEY

    console.print(f"    Consultando NVD ({search_type_log}) (delay: {current_delay}s)...", highlight=False)
    try:
        response = requests.get(NVD_API_BASE_URL, params=params, headers=headers, timeout=30)
        time.sleep(current_delay)
        response.raise_for_status()
        data = response.json()
        if data.get("vulnerabilities"):
            for cve_item_wrapper in data["vulnerabilities"]:
                cve_data = cve_item_wrapper.get("cve", {})
                cve_id = cve_data.get("id", "N/A")
                description = "No English description available."
                if cve_data.get("descriptions"):
                    for desc_entry in cve_data["descriptions"]:
                        if desc_entry.get("lang") == "en":
                            description = desc_entry.get("value", description)
                            break
                cvss_v3_score, cvss_v3_vector, severity = None, None, None
                metrics = cve_data.get("metrics", {})
                cvss_metrics_v31, cvss_metrics_v30 = metrics.get("cvssMetricV31"), metrics.get("cvssMetricV30")
                if cvss_metrics_v31:
                    cvss_data_details = cvss_metrics_v31[0].get("cvssData", {})
                    cvss_v3_score, cvss_v3_vector, severity = cvss_data_details.get("baseScore"), cvss_data_details.get(
                        "vectorString"), cvss_metrics_v31[0].get("baseSeverity")
                elif cvss_metrics_v30:
                    cvss_data_details = cvss_metrics_v30[0].get("cvssData", {})
                    cvss_v3_score, cvss_v3_vector, severity = cvss_data_details.get("baseScore"), cvss_data_details.get(
                        "vectorString"), cvss_metrics_v30[0].get("baseSeverity")
                published_date = cve_data.get("published", "N/A")
                vulnerabilities_found.append({
                    "cve_id": cve_id, "description": description, "cvss_v3_score": cvss_v3_score,
                    "severity": severity, "cvss_v3_vector": cvss_v3_vector, "published_date": published_date,
                    "link": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id != "N/A" else "N/A", "source": "NVD"
                })
            console.print(f"      [green]NVD: {len(vulnerabilities_found)} CVEs para '{search_type_log}'[/green]",
                          highlight=False)
        else:
            console.print(
                f"      [yellow]NVD: Nenhuma CVE para '{search_type_log}' (totalResults: {data.get('totalResults', 0)})[/yellow]",
                highlight=False)
    except requests.exceptions.HTTPError as http_err:
        status_code = http_err.response.status_code if http_err.response else 'N/A'
        if status_code == 404:
            console.print(
                f"  [yellow]NVD API Erro 404 (Not Found) para '{search_type_log}'. Termo/CPE pode não existir ou não ter CVEs.[/yellow]",
                highlight=False)
        elif status_code == 403:
            console.print(
                f"  [red]NVD API Erro 403 (Forbidden) para '{search_type_log}'. Rate limit? Verifique chave/delay.[/red]",
                highlight=False)
        else:
            console.print(
                f"  [red]NVD API HTTP error para '{search_type_log}': {http_err} (Status: {status_code})[/red]",
                highlight=False)
    except requests.exceptions.RequestException as req_err:
        console.print(f"  [red]NVD API request error para '{search_type_log}': {req_err}[/red]", highlight=False)
    except Exception as e:
        console.print(f"  [red]Erro processando NVD para '{search_type_log}': {e}[/red]", highlight=False)
    return vulnerabilities_found

def add_nvd_vulnerability_info(structured_data, nvd_api_key=None):
    console.print("\n[cyan][*] Consultando NVD para vulnerabilidades conhecidas...[/cyan]")
    if not isinstance(structured_data, list):
        console.print("[yellow][!] Nenhum dado estruturado para consultar NVD.[/yellow]")
        return
    for host_info in track(structured_data, description="Consultando NVD..."):
        if not isinstance(host_info.get("services"), list):
            continue
        for service in host_info["services"]:
            version = service.get("version")
            product_name_from_sv = service.get("nmap_sv_info", {}).get("product")
            service_name_initial = service.get("service_name")
            product_to_query = product_name_from_sv if product_name_from_sv else service_name_initial

            service["vulnerabilities"] = []
            if product_to_query and version:
                nvd_vulns = query_nvd_for_vulnerabilities(product_to_query, version, nvd_api_key)
                if nvd_vulns:
                    service["vulnerabilities"].extend(nvd_vulns)
                if not service["vulnerabilities"] and not any(
                        "Intervalo de versões detectado" in v.get("info", "") for v in nvd_vulns if
                        isinstance(v, dict)):
                    service[
                        "vulnerability_query_status"] = f"Nenhuma vulnerabilidade encontrada por NVD para {product_to_query} {version}"
            elif product_to_query:
                service["security_notes"] = ["Versão específica não identificada.",
                                             "Recomenda-se investigação manual e verificação de patches."]
            else:
                service["security_notes"] = ["Serviço não claramente identificado.",
                                             "Recomenda-se investigação manual."]
    console.print("[green][+] Consultas ao NVD concluídas.[/green]")
