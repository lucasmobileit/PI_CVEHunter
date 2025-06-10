import json
from pymongo import MongoClient
from datetime import datetime
import hashlib


def SaveMongo() :
    # Caminho do arquivo JSON (deve estar na mesma pasta do script)
    json_file = "scan_results_final_report.json"

    # Conecta ao MongoDB
    mongo_uri = "mongodb+srv://login:password@cluster0.ozsm1jh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
    client = MongoClient(mongo_uri)

    # Escolher o banco de dados e a coleção
    # "vulnerability_db" é o nome do banco, "scan_results" é o nome da coleção
    db = client["vulnerability_db"]
    collection = db["scan_results"]

    # Definir a data do scan (usando a data atual em formato ISO 8601)
    scan_date = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")  # Exemplo: "2025-06-10T09:29:00Z"

    # Tentar ler o arquivo JSON
    try:
        with open(json_file, 'r') as file:
            data = json.load(file)  # Carrega o JSON como uma lista de dicionários
            print(f"Arquivo {json_file} carregado com sucesso!")
    except:
        print(f"Erro: Não consegui abrir o arquivo {json_file}. Verifique se ele existe.")
        exit()

    # Lista para armazenar os documentos que serão salvos no MongoDB
    documents = []

    # Para cada host no JSON
    for host_data in data:
        host = host_data.get("host", "")  # Pegar o campo "host"
        services = host_data.get("services", [])  # Pegar a lista de serviços

        # Para cada serviço no host
        for service in services:
            # Pegar os campos do serviço
            port = str(service.get("port", ""))  # Converter para string
            protocol = service.get("protocol", "")
            service_name = service.get("service_name", "")
            details = service.get("details", "")
            # Pegar os campos do nmap_sv_info, se existir
            nmap_info = service.get("nmap_sv_info", {})
            nmap_service_name = nmap_info.get("nmap_service_name", "")
            product = nmap_info.get("product", "")
            version = nmap_info.get("version", "")
            extrainfo = nmap_info.get("extrainfo", "")
            ostype = nmap_info.get("ostype", "")
            cpes = ", ".join(nmap_info.get("cpes", []))  # Juntar array em string com vírgulas

            # Pegar as vulnerabilidades do serviço
            vulnerabilities = service.get("vulnerabilities", [])

            # Se não houver vulnerabilidades, criar um documento sem vulnerabilidade
            if not vulnerabilities:
                # Criar um ID único combinando host, port, cve_id (vazio), e scan_date
                record_id = hashlib.md5(f"{host}:{port}:::{scan_date}".encode()).hexdigest()
                document = {
                    "record_id": record_id,
                    "scan_date": scan_date,
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "service_name": service_name,
                    "details": details,
                    "nmap_service_name": nmap_service_name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "ostype": ostype,
                    "cpes": cpes,
                    "cve_id": "",
                    "description": "",
                    "severity": "",
                    "cvss_v3_score": "",
                    "cvss_v3_vector": "",
                    "published_date": "",
                    "link": "",
                    "source": ""
                }
                documents.append(document)
            else:
                # Para cada vulnerabilidade no serviço
                for vuln in vulnerabilities:
                    # Converter published_date para formato ISO 8601, se existir
                    published_date = vuln.get("published_date", "")
                    if published_date:
                        try:
                            # Tenta converter para ISO 8601 (remove milissegundos extras)
                            published_date = datetime.strptime(published_date, "%Y-%m-%dT%H:%M:%S.%f").strftime("%Y-%m-%dT%H:%M:%SZ")
                        except ValueError:
                            published_date = ""  # Se falhar, deixa vazio

                    # Criar um ID único combinando host, port, cve_id, e scan_date
                    cve_id = vuln.get("cve_id", "")
                    record_id = hashlib.md5(f"{host}:{port}:{cve_id}:{scan_date}".encode()).hexdigest()

                    document = {
                        "record_id": record_id,
                        "scan_date": scan_date,
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "service_name": service_name,
                        "details": details,
                        "nmap_service_name": nmap_service_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "ostype": ostype,
                        "cpes": cpes,
                        "cve_id": cve_id,
                        "description": vuln.get("description", ""),
                        "severity": vuln.get("severity", ""),
                        "cvss_v3_score": vuln.get("cvss_v3_score", ""),
                        "cvss_v3_vector": vuln.get("cvss_v3_vector", ""),
                        "published_date": published_date,
                        "link": vuln.get("link", ""),
                        "source": vuln.get("source", "")
                    }
                    documents.append(document)

    # Tentar salvar os documentos no MongoDB
    try:
        if documents:
            collection.insert_many(documents)
            print(f"Sucesso: {len(documents)} documentos salvos no MongoDB!")
        else:
            print("Aviso: Nenhum documento para salvar. O JSON pode estar vazio.")
    except:
        print("Erro: Não consegui salvar no MongoDB. Verifique o URI ou a conexão.")
        exit()

    # Criar índices para melhorar consultas no Power BI
    try:
        collection.create_index([("host", 1), ("port", 1), ("cve_id", 1)])
        print("Índice criado para host, port e cve_id.")
    except:
        print("Aviso: Não consegui criar o índice, mas os dados foram salvos.")

    # Fechar a conexão com o MongoDB
    client.close()
    print("Conexão com MongoDB fechada.")