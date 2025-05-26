from fastapi import FastAPI, Request
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
    year: str = "",           # <-- CAMBIO: ahora es string siempre
    product: str = ""
):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)

    # Si hay filtro por producto, se hace JOIN con cve_cpe, si no, consulta solo cve_entries
    if product:
        query = """
            SELECT DISTINCT e.*
            FROM cve_entries e
            JOIN cve_cpe c ON e.cve_id = c.cve_id
            WHERE c.product LIKE %s
        """
        params = [f"%{product}%"]
        if q:
            query += " AND (e.description_en LIKE %s OR e.cve_id LIKE %s)"
            params.extend([f"%{q}%", f"%{q}%"])
        if severity:
            query += " AND e.severity_v3 = %s"
            params.append(severity)
        if year.isdigit():         # <-- Solo añade si hay número válido
            query += " AND YEAR(e.published_date) = %s"
            params.append(int(year))
        query += " ORDER BY e.published_date DESC LIMIT 100"
        cur.execute(query, params)
    else:
        query = "SELECT * FROM cve_entries WHERE 1=1"
        params = []
        if q:
            query += " AND (description_en LIKE %s OR cve_id LIKE %s)"
            params.extend([f"%{q}%", f"%{q}%"])
        if severity:
            query += " AND severity_v3 = %s"
            params.append(severity)
        if year.isdigit():
            query += " AND YEAR(published_date) = %s"
            params.append(int(year))
        query += " ORDER BY published_date DESC LIMIT 100"
        cur.execute(query, params)

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

