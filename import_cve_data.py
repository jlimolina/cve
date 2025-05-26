import os
import json
import zipfile
import requests
from dotenv import load_dotenv
import mysql.connector
from tqdm import tqdm
import traceback

load_dotenv()

# Conexión a la base de datos
conn = mysql.connector.connect(
    host=os.getenv("DB_HOST"),
    user=os.getenv("DB_USER"),
    password=os.getenv("DB_PASS"),
    database=os.getenv("DB_NAME")
)
cur = conn.cursor()

# ===============================
# CREACIÓN DE TABLAS SI NO EXISTEN
# ===============================

cur.execute("""
CREATE TABLE IF NOT EXISTS cve_entries (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL UNIQUE,
    source VARCHAR(255),
    published_date DATETIME,
    last_modified DATETIME,
    status VARCHAR(50),
    description_en TEXT,
    description_es TEXT,
    cvss_score_v3 FLOAT,
    severity_v3 VARCHAR(20),
    cvss_vector_v3 TEXT,
    cvss_score_v4 FLOAT,
    cvss_vector_v4 TEXT,
    source_link TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS cve_cpe (
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(30) NOT NULL,
    cpe_uri TEXT,
    vendor VARCHAR(255),
    product VARCHAR(255),
    version VARCHAR(255),
    FOREIGN KEY (cve_id) REFERENCES cve_entries(cve_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
""")
conn.commit()
# ===============================

ZIP_URLS = [
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2024.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2023.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2022.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2021.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2020.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2019.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2018.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2017.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2016.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2015.json.zip",
    "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2014.json.zip",
    ]

def download_zip(url):
    filename = url.split("/")[-1]
    if os.path.exists(filename):
        print(f"📁 Ya existe {filename}, saltando descarga.")
        return filename
    print(f"🔽 Descargando {filename}...")
    r = requests.get(url, stream=True)
    with open(filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=8192):
            f.write(chunk)
    return filename

# ---- FUNCIÓN CORREGIDA PARA AMBOS FORMATOS ----
def insert_cpe_data(cve_id, configurations):
    # Si es dict (viejo formato)
    if isinstance(configurations, dict):
        nodes = configurations.get("nodes", [])
        _insert_cpe_nodes(cve_id, nodes)
    # Si es lista (formato nuevo NVD 2024+)
    elif isinstance(configurations, list):
        for config in configurations:
            if isinstance(config, dict) and "nodes" in config:
                nodes = config["nodes"]
                _insert_cpe_nodes(cve_id, nodes)
    # Si no es ninguno, ignorar

def _insert_cpe_nodes(cve_id, nodes):
    for node in nodes:
        if not isinstance(node, dict):
            continue
        matches = node.get("cpeMatch", [])
        for match in matches:
            if not isinstance(match, dict):
                continue
            if "criteria" in match:
                cpe_uri = match["criteria"]
                parts = cpe_uri.split(":")
                if len(parts) >= 6:
                    vendor = parts[3]
                    product = parts[4]
                    version = parts[5] if parts[5] != '*' else None
                    cur.execute("""
                        INSERT IGNORE INTO cve_cpe (cve_id, cpe_uri, vendor, product, version)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (cve_id, cpe_uri, vendor, product, version))

def insert_cve(cve):
    try:
        cve_id = cve.get("id")
        source = cve.get("sourceIdentifier")
        published = cve.get("published")
        modified = cve.get("lastModified")
        status = cve.get("vulnStatus")

        desc_en, desc_es = None, None
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc_en = d.get("value")
            elif d.get("lang") == "es":
                desc_es = d.get("value")

        # MÉTRICAS robustas ante cualquier formato extraño
        cvss_v3, sev_v3, vec_v3 = None, None, None
        cvss_v4, vec_v4 = None, None

        metrics = cve.get("metrics", {})
        if isinstance(metrics, dict):
            v3 = metrics.get("cvssMetricV31", [])
            if isinstance(v3, list) and v3 and isinstance(v3[0], dict):
                data = v3[0].get("cvssData", {})
                if isinstance(data, dict):
                    cvss_v3 = data.get("baseScore")
                    sev_v3 = data.get("baseSeverity")
                    vec_v3 = data.get("vectorString")
            v4 = metrics.get("cvssMetricV40", [])
            if isinstance(v4, list) and v4 and isinstance(v4[0], dict):
                data = v4[0].get("cvssData", {})
                if isinstance(data, dict):
                    cvss_v4 = data.get("baseScore")
                    vec_v4 = data.get("vectorString")

        link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        cur.execute("""
            INSERT IGNORE INTO cve_entries (
                cve_id, source, published_date, last_modified, status,
                description_en, description_es, cvss_score_v3, severity_v3, cvss_vector_v3,
                cvss_score_v4, cvss_vector_v4, source_link
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            cve_id, source, published, modified, status,
            desc_en, desc_es, cvss_v3, sev_v3, vec_v3,
            cvss_v4, vec_v4, link
        ))

        # Ahora maneja ambos formatos de configuraciones
        configurations = cve.get("configurations", {})
        insert_cpe_data(cve_id, configurations)

    except Exception as e:
        print(f"❌ Error con {cve.get('id', 'UNKNOWN')}: {e}")
        traceback.print_exc()

def process_json(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
        vulnerabilities = data.get("vulnerabilities", [])
        for v in tqdm(vulnerabilities, desc=f"Procesando {file_path}"):
            if "cve" in v and isinstance(v["cve"], dict):
                insert_cve(v["cve"])
            else:
                print(f"❌ Entrada inesperada, no tiene 'cve' dict: {v}")

def main():
    for url in ZIP_URLS:
        zip_file = download_zip(url)
        with zipfile.ZipFile(zip_file, 'r') as z:
            z.extractall()
            for extracted_file in z.namelist():
                process_json(extracted_file)
                os.remove(extracted_file)
    conn.commit()
    cur.close()
    conn.close()
    print("✅ Todos los datos han sido cargados en la base de datos.")

if __name__ == "__main__":
    main()

