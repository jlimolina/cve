# CVE Importer

Importador y visualizador de CVE + CPE usando datos de la NVD.

## Requisitos

- Python 3.9+
- MariaDB o MySQL
- `requirements.txt` con:
  - fastapi
  - jinja2
  - mysql-connector-python
  - python-dotenv
  - requests
  - tqdm
  - uvicorn

## Uso

1. Crea tu base de datos MariaDB/MySQL y configura un usuario.
2. Copia `.env.example` a `.env` y pon tus credenciales.
3. Instala dependencias:
   ```bash
   pip install -r requirements.txt

