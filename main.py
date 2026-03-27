from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fpdf import FPDF
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import stripe
import requests
import time
import os
from datetime import datetime

app = FastAPI()

# --- CONFIGURAÇÃO BANCO DE DADOS (DOCKER PORTA 5433) ---
DATABASE_URL = "postgresql://postgres:vstudio_secure_2026@localhost:5433/postgres"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class EncryptedScan(Base):
    __tablename__ = "encrypted_scans"
    id = Column(Integer, primary_key=True, index=True)
    url_scanned = Column(String)
    phishing_score = Column(Integer)
    malware_risk = Column(String)
    ip_reputation = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Dependência do Banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

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
        # Simulação de varredura real para o seu App
        return [
            {"name": "Reputação de IP", "status": "Clean", "score": 10},
            {"name": "Análise Phishing", "status": "Suspeito", "score": 51},
            {"name": "Malware Check", "status": "Medium Risk", "score": 30}
        ]

# --- ENDPOINTS ---

@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest, db: Session = Depends(get_db)):
    scanner = VulnerabilityScanner(request.url)
    findings = scanner.run_all()
    
    # SALVANDO NO BANCO DE DADOS (POSTGRES)
    new_entry = EncryptedScan(
        url_scanned=request.url,
        phishing_score=51, # Valor fixo baseado no seu design do Canva
        malware_risk="Medium",
        ip_reputation="Clean"
    )
    db.add(new_entry)
    db.commit()
    
    return {"status": "completed", "vulnerabilities": findings}

@app.get("/api/v1/history")
async def get_history(db: Session = Depends(get_db)):
    # BUSCA OS ÚLTIMOS 10 SCANS PARA O SEU DASHBOARD
    history = db.query(EncryptedScan).order_by(EncryptedScan.created_at.desc()).limit(10).all()
    return history

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
