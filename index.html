import time
import ssl
import socket
import requests
import dns.resolver
from datetime import datetime
from typing import List
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

app = FastAPI(title="Visual Studio Security Engine")

# Habilitar CORS para o seu Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str

class VulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.results = []
        self.sqli_payloads = ["'", "''", "1' OR '1'='1", "SLEEP(5)"]
        self.common_subs = ["www", "dev", "api", "test", "staging", "admin", "webmail"]

    def check_ssl(self):
        """Verifica a saúde do certificado SSL."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (expire_date - datetime.now()).days
                    if days_left < 30:
                        self.results.append({
                            "name": "Certificado SSL Expirando",
                            "severity": "medium",
                            "layer": "SSL/TLS",
                            "desc": f"O certificado expira em {days_left} dias. Renove para evitar bloqueios."
                        })
        except:
            self.results.append({
                "name": "Falha na Verificação SSL",
                "severity": "high",
                "layer": "SSL/TLS",
                "desc": "Não foi possível validar o handshake SSL/TLS."
            })

    def check_headers_and_files(self):
        """Verifica headers de segurança e exposição de arquivos sensíveis."""
        try:
            res = requests.get(self.url, timeout=10, verify=False)
            headers = res.headers
            
            checks = {
                "Content-Security-Policy": "critical",
                "X-Frame-Options": "high",
                "Strict-Transport-Security": "high",
                "X-Content-Type-Options": "medium"
            }
            for h, sev in checks.items():
                if h not in headers:
                    self.results.append({
                        "name": f"Header {h} Ausente",
                        "severity": sev,
                        "layer": "HTTP Headers",
                        "desc": "A ausência deste header facilita ataques de Clickjacking ou Injeção."
                    })

            for path in ["/.env", "/.git/config", "/phpmyadmin/"]:
                if requests.get(f"{self.url.rstrip('/')}{path}", timeout=5).status_code == 200:
                    self.results.append({
                        "name": f"Arquivo Exposto: {path}",
                        "severity": "critical",
                        "layer": "Info Leak",
                        "desc": "Arquivos de configuração ou sistemas internos acessíveis publicamente."
                    })
        except: pass

    def run_subdomain_recon(self):
        """Busca subdomínios ativos via DNS."""
        found = []
        for sub in self.common_subs:
            try:
                target = f"{sub}.{self.domain}"
                dns.resolver.resolve(target, 'A')
                found.append(target)
            except: continue
        
        if found:
            self.results.append({
                "name": f"{len(found)} Subdomínios Encontrados",
                "severity": "low",
                "layer": "Infraestrutura",
                "desc": f"Superfície de ataque identificada: {', '.join(found)}"
            })

    def run_fuzzer(self):
        """Testa injeção SQL em parâmetros da URL."""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in self.sqli_payloads:
                test_params = params.copy()
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                
                try:
                    start = time.time()
                    res = requests.get(test_url, timeout=10)
                    duration = time.time() - start
                    
                    if any(err in res.text.lower() for err in ["sql syntax", "mysql_fetch", "sqlite"]):
                        self.results.append({
                            "name": "SQL Injection (Error-based)",
                            "severity": "critical",
                            "layer": "SQL Injection",
                            "desc": f"Vulnerabilidade crítica no parâmetro '{param}'."
                        })
                        break
                    if "SLEEP" in payload and duration > 4:
                        self.results.append({
                            "name": "Blind SQLi (Time-based)",
                            "severity": "critical",
                            "layer": "SQL Injection",
                            "desc": f"Injeção detectada via delay de resposta no parâmetro '{param}'."
                        })
                except: continue

@app.post("/api/v1/scan")
async def start_audit(request: ScanRequest):
    scanner = VulnerabilityScanner(request.url)
    
    # Execução das Camadas
    scanner.run_subdomain_recon()
    scanner.check_ssl()
    scanner.check_headers_and_files()
    scanner.run_fuzzer()
    
    return {
        "status": "success",
        "url": request.url,
        "timestamp": datetime.now().isoformat(),
        "vulnerabilities": scanner.results
    }
