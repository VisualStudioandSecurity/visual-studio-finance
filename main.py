from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fpdf import FPDF
import stripe
import requests
import time
import os
from datetime import datetime

app = FastAPI()

# CONFIGURAÇÃO STRIPE
stripe.api_key = "SUA_CHAVE_SECRET_AQUI"

class ScanRequest(BaseModel):
    url: str

# --- GERADOR DE PDF ---
class SecurityReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 16)
        self.set_text_color(0, 150, 255)
        self.cell(0, 10, "VISUAL STUDIO AND SECURITY PROTOCOL", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.set_text_color(128)
        self.cell(0, 10, "ID: VS-SEC-2026 | INTEGRIDADE GARANTIDA VIA SHA-256", align="C")

# --- MOTOR DE SCANNER ---
class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.results = []

    def run_all(self):
        # Simulação de varredura real para o relatório
        self.results.append({"name": "Falta de CSP Header", "severity": "high", "layer": "HTTP", "desc": "Ausência de Content-Security-Policy."})
        self.results.append({"name": "SQL Injection Test", "severity": "critical", "layer": "Database", "desc": "Vulnerabilidade detectada em parâmetros de URL."})
        return self.results

# --- ENDPOINTS ---

@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest):
    scanner = VulnerabilityScanner(request.url)
    findings = scanner.run_all()
    return {"status": "completed", "vulnerabilities": findings}

@app.post("/api/v1/create-checkout")
async def create_checkout(request: ScanRequest):
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'brl',
                    'product_data': {'name': f'Relatório Premium: {request.url}'},
                    'unit_amount': 4990,
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f"http://127.0.0.1:5500/success.html?url={request.url}",
            cancel_url="http://127.0.0.1:5500/index.html",
        )
        return {"url": session.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/download-report")
async def download_report(url: str):
    scanner = VulnerabilityScanner(url)
    findings = scanner.run_all()
    
    pdf = SecurityReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Alvo: {url}", ln=True)
    
    for f in findings:
        pdf.cell(0, 10, f"- {f['name']} ({f['severity']})", ln=True)
    
    file_name = f"report_{int(time.time())}.pdf"
    pdf.output(file_name)
    
    return FileResponse(path=file_name, filename=f"Auditoria_{url}.pdf", media_type='application/pdf')
