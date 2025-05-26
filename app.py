from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import mysql.connector
import os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()
templates = Jinja2Templates(directory="templates")

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        database=os.getenv("DB_NAME")
    )

@app.get("/", response_class=HTMLResponse)
async def home(
    request: Request,
    q: str = "",
    severity: str = "",
    year: str = "",
    product: str = ""
):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    # Selecciona campos de cve_entries y el primer producto relacionado (si existe)
    base_query = """
        SELECT e.*, MIN(c.product) AS product
        FROM cve_entries e
        LEFT JOIN cve_cpe c ON e.cve_id = c.cve_id
        WHERE 1=1
    """
    params = []

    if product:
        base_query += " AND c.product LIKE %s"
        params.append(f"%{product}%")
    if q:
        base_query += " AND (e.description_en LIKE %s OR e.cve_id LIKE %s)"
        params.extend([f"%{q}%", f"%{q}%"])
    if severity:
        base_query += " AND e.severity_v3 = %s"
        params.append(severity)
    if year.isdigit():
        base_query += " AND YEAR(e.published_date) = %s"
        params.append(int(year))

    # Agrupa por CVE para no repetir filas y muestra solo 100 últimas
    base_query += " GROUP BY e.cve_id ORDER BY e.published_date DESC LIMIT 100"

    cur.execute(base_query, params)
    results = cur.fetchall()
    cur.close()
    conn.close()

    return templates.TemplateResponse("index.html", {
        "request": request,
        "results": results,
        "q": q,
        "severity": severity,
        "year": year,
        "product": product
    })

@app.get("/cve/{cve_id}", response_class=HTMLResponse)
async def cve_detail(request: Request, cve_id: str):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    # Info principal de la CVE
    cur.execute(
        "SELECT * FROM cve_entries WHERE cve_id = %s LIMIT 1",
        (cve_id,)
    )
    entry = cur.fetchone()

    # Productos afectados
    cur.execute(
        "SELECT vendor, product, version FROM cve_cpe WHERE cve_id = %s",
        (cve_id,)
    )
    products = cur.fetchall()

    cur.close()
    conn.close()

    if not entry:
        raise HTTPException(status_code=404, detail="CVE no encontrada")

    return templates.TemplateResponse("detail.html", {
        "request": request,
        "entry": entry,
        "products": products,
    })

