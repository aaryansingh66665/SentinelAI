from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os
from pydantic import BaseModel
from typing import List

from agents.agents import CyberGuardAgentPipeline, COMPANY_PROFILES, generate_comprehensive_recon
from tools.security import validate_target, validate_ip, validate_ports, TokenBucketRateLimiter, decrypt_data

# Import real scanner
try:
    from tools.scanner import full_recon_scan, get_service_name as scanner_get_service, PORT_SERVICE_MAP
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False
    print("[WARNING] scanner module not available. Custom scans will use simulated data.")

app = FastAPI(
    title="SentinelAI Server",
    description="SentinelAI Multi-agent cybersecurity assistant backend API",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Attempt to load encrypted API key
decryption_password = os.environ.get("DECRYPTION_PASSWORD")
encrypted_env_path = os.path.join(os.path.dirname(__file__), "..", ".env.enc")
if not os.environ.get("GEMINI_API_KEY") and os.path.exists(encrypted_env_path) and decryption_password:
    try:
        with open(encrypted_env_path, "r") as f:
            encrypted_content = f.read().strip()
        decrypted_key = decrypt_data(encrypted_content, decryption_password)
        os.environ["GEMINI_API_KEY"] = decrypted_key
        print("[SECURITY] Successfully decrypted and loaded GEMINI_API_KEY from .env.enc")
    except Exception as e:
        print(f"[SECURITY] Failed to decrypt .env.enc: {e}")

# Initialize Rate Limiter: 0.1 rate (1 token per 10s), max capacity 3
limiter = TokenBucketRateLimiter(rate=0.1, capacity=3)

# Initialize Agent Pipeline
pipeline = CyberGuardAgentPipeline()

class CustomScanPayload(BaseModel):
    name: str
    description: str
    target: str
    ip: str
    ports: List[int]

PORT_CVE_MAPPING = {
    22: {
        "id": "CVE-2019-1589",
        "title": "SSH Weak Configuration / Outdated Version",
        "severity": "LOW",
        "cve": "CVE-2019-1589",
        "port": 22,
        "service": "ssh",
        "product": "OpenSSH",
        "version": "7.4p1",
        "description": "The SSH server is outdated and configured to accept password-based authentication, increasing vulnerability to brute force attacks.",
        "remediation": "Disable password-based authentication in sshd_config and enforce SSH key-based login. Upgrade OpenSSH to version 8.0+."
    },
    80: {
        "id": "CVE-2018-1311",
        "title": "Apache Xerces-C XML Parser Denial of Service",
        "severity": "MEDIUM",
        "cve": "CVE-2018-1311",
        "port": 80,
        "service": "http",
        "product": "Apache HTTPD",
        "version": "2.4.41",
        "description": "An issue in Apache Xerces-C XML parser allows remote attackers to cause a denial of service (CPU consumption) via a crafted XML document.",
        "remediation": "Update libraries using Xerces-C to the latest secure version, or restrict HTTP upload sizes and parse settings."
    },
    443: {
        "id": "SEC-SSL-01",
        "title": "SSL/TLS Outdated Protocol Configuration (TLS 1.0/1.1 Enabled)",
        "severity": "LOW",
        "cve": "N/A - Protocol Suite",
        "port": 443,
        "service": "https",
        "product": "nginx",
        "version": "1.18.0",
        "description": "The Apache server supports deprecated SSL versions TLS 1.0 and TLS 1.1, which contain cryptographic vulnerabilities that could allow interception of traffic.",
        "remediation": "Modify SSL settings to disable TLS 1.0 and 1.1. Restrict cipher configurations to TLS 1.2 and TLS 1.3 only."
    },
    445: {
        "id": "CVE-2017-0144",
        "title": "MS17-010 EternalBlue Windows SMB Remote Code Execution",
        "severity": "CRITICAL",
        "cve": "CVE-2017-0144",
        "port": 445,
        "service": "microsoft-ds",
        "product": "Windows SMB",
        "version": "SMBv1",
        "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets. This is famously exploited by WannaCry and NotPetya ransomwares.",
        "remediation": "Disable SMBv1 completely in Windows Features. Install MS17-010 security update. Immediately block port 445 at the network boundary firewall."
    },
    3306: {
        "id": "CVE-2021-27928",
        "title": "MySQL Remote Code Execution via Extension Loading",
        "severity": "CRITICAL",
        "cve": "CVE-2021-27928",
        "port": 3306,
        "service": "mysql",
        "product": "MySQL",
        "version": "5.7.22",
        "description": "The MariaDB/MySQL server allows remote authenticated users to trigger remote code execution by loading a shared library from a SQL query. Exposed port 3306 with default/weak credentials increases this risk significantly.",
        "remediation": "Do not expose MySQL port 3306 to the public internet. Bind it to localhost (127.0.0.1) or restrict access via firewall rules to specific trusted IPs. Upgrade database version to 5.7.34+ or 8.0.24+."
    },
    3389: {
        "id": "CVE-2019-0708",
        "title": "BlueKeep Remote Desktop Protocol Remote Code Execution",
        "severity": "CRITICAL",
        "cve": "CVE-2019-0708",
        "port": 3389,
        "service": "ms-wbt-server",
        "product": "Microsoft Terminal Services",
        "version": "RDP",
        "description": "A remote code execution vulnerability exists in Remote Desktop Services (formerly known as Terminal Services) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
        "remediation": "Apply the BlueKeep security patch from Microsoft. Enforce Network Level Authentication (NLA) for RDP. Restrict RDP port 3389 via VPN and firewall rules."
    },
    6379: {
        "id": "SEC-REDIS-01",
        "title": "Exposed Unauthenticated Redis Server",
        "severity": "HIGH",
        "cve": "N/A - Configuration Issue",
        "port": 6379,
        "service": "redis",
        "product": "Redis key-value store",
        "version": "5.0.0",
        "description": "The Redis key-value database is exposed to the public internet without password authentication. An attacker can execute arbitrary commands, read sensitive database contents, or write keys to write files on the server.",
        "remediation": "Enable password authentication in redis.conf (`requirepass`). Bind Redis to local interfaces only (`bind 127.0.0.1`). Use firewall rules to block port 6379 from WAN."
    },
    8080: {
        "id": "CVE-2018-1000861",
        "title": "Jenkins Remote Code Execution via Stapler web framework",
        "severity": "CRITICAL",
        "cve": "CVE-2018-1000861",
        "port": 8080,
        "service": "http-proxy",
        "product": "Jenkins",
        "version": "2.121",
        "description": "An improper accessibility check in the Stapler web framework of Jenkins allows unauthenticated remote attackers to execute arbitrary code via HTTP GET requests.",
        "remediation": "Upgrade Jenkins to LTS 2.150.1 or higher. Do not expose administrative CI/CD control portals to the public internet; place them behind a secure VPN or proxy configuration."
    },
    # ── New Port CVE Mappings ──
    21: {
        "id": "CVE-2010-4221",
        "title": "ProFTPD Telnet IAC Stack Overflow Remote Code Execution",
        "severity": "CRITICAL",
        "cve": "CVE-2010-4221",
        "port": 21,
        "service": "ftp",
        "product": "ProFTPD",
        "version": "1.3.3c",
        "description": "A stack overflow in ProFTPD's mod_site_misc module allows unauthenticated remote attackers to execute arbitrary code. FTP transmits credentials in plaintext, enabling trivial credential interception.",
        "remediation": "Disable FTP entirely. Migrate to SFTP (SSH port 22) or FTPS with explicit TLS. If FTP is required, restrict access by IP and enforce strong password policies."
    },
    23: {
        "id": "SEC-TELNET-01",
        "title": "Telnet Service Exposed — Unencrypted Remote Access Protocol",
        "severity": "CRITICAL",
        "cve": "N/A - Protocol Design Flaw",
        "port": 23,
        "service": "telnet",
        "product": "Linux telnetd",
        "version": "0.17",
        "description": "Telnet transmits all data, including credentials, in cleartext over the network. Any network observer can capture usernames, passwords, and session data in real time.",
        "remediation": "Disable Telnet immediately. Replace with SSH for all remote access. Block port 23 at the firewall unconditionally."
    },
    25: {
        "id": "SEC-SMTP-01",
        "title": "SMTP Open Relay / Exposed Mail Server",
        "severity": "HIGH",
        "cve": "N/A - Configuration Issue",
        "port": 25,
        "service": "smtp",
        "product": "Postfix SMTP",
        "version": "3.3.0",
        "description": "An exposed SMTP port without authentication can be leveraged as an open mail relay, enabling spammers to send unsolicited emails through the server. This can damage domain reputation and lead to blocklisting.",
        "remediation": "Require SMTP authentication (SASL). Configure strict relay restrictions to only allow authenticated users. Enable TLS for all SMTP connections. Monitor for abuse with rate-limiting."
    },
    110: {
        "id": "SEC-POP3-01",
        "title": "POP3 Service Exposed — Unencrypted Email Retrieval",
        "severity": "MEDIUM",
        "cve": "N/A - Protocol Issue",
        "port": 110,
        "service": "pop3",
        "product": "Dovecot POP3",
        "version": "2.3.x",
        "description": "POP3 without TLS transmits email content and credentials in plaintext. An attacker on the same network can intercept mail, usernames, and passwords.",
        "remediation": "Disable plain POP3 (port 110) and enforce POP3S on port 995. Configure TLS encryption in Dovecot. Prefer IMAPS over POP3S for modern clients."
    },
    143: {
        "id": "SEC-IMAP-01",
        "title": "IMAP Service Exposed — Unencrypted Email Protocol",
        "severity": "MEDIUM",
        "cve": "N/A - Protocol Issue",
        "port": 143,
        "service": "imap",
        "product": "Dovecot IMAP",
        "version": "2.3.x",
        "description": "IMAP without STARTTLS or TLS wrapping allows credentials and email contents to be transmitted in cleartext, exposing all communications to network sniffing.",
        "remediation": "Enforce STARTTLS on all IMAP connections. Migrate clients to IMAPS on port 993. Disable plain IMAP if IMAPS is available."
    },
    389: {
        "id": "SEC-LDAP-01",
        "title": "LDAP Anonymous Bind / Unauthenticated Directory Access",
        "severity": "HIGH",
        "cve": "N/A - Misconfiguration",
        "port": 389,
        "service": "ldap",
        "product": "OpenLDAP",
        "version": "2.4.x",
        "description": "LDAP exposed on the public internet with anonymous bind enabled allows attackers to enumerate all directory objects including usernames, email addresses, organizational units, and group memberships.",
        "remediation": "Disable anonymous LDAP binds. Restrict LDAP access to internal networks only. Enable LDAPS on port 636. Use strong bind account credentials with minimal permissions."
    },
    5432: {
        "id": "CVE-2019-10164",
        "title": "PostgreSQL Stack Overflow in Short String Handling",
        "severity": "HIGH",
        "cve": "CVE-2019-10164",
        "port": 5432,
        "service": "postgresql",
        "product": "PostgreSQL",
        "version": "11.3",
        "description": "PostgreSQL versions 10.x, 11.x before 11.4 and 10.9 contain a stack buffer overflow in short-string handling that can be triggered by authenticated users and may lead to arbitrary code execution.",
        "remediation": "Upgrade PostgreSQL to version 11.4+ or 10.9+. Bind PostgreSQL to localhost (127.0.0.1) only. Never expose port 5432 to the public internet."
    },
    8443: {
        "id": "SEC-HTTPS-ALT-01",
        "title": "Alternative HTTPS Port Exposed — Potential Misconfigured Service",
        "severity": "MEDIUM",
        "cve": "N/A - Configuration Issue",
        "port": 8443,
        "service": "https-alt",
        "product": "Apache Tomcat",
        "version": "9.0.x",
        "description": "An HTTPS service running on a non-standard port (8443) is often a development or staging endpoint. These services may lack proper security hardening, authentication enforcement, or certificate validation.",
        "remediation": "Audit the service running on port 8443. Ensure it requires authentication. Apply the same security headers and TLS configuration as the primary HTTPS endpoint. Block if not required externally."
    },
    9200: {
        "id": "CVE-2021-22145",
        "title": "Elasticsearch Exposure — Unauthenticated Data Access",
        "severity": "CRITICAL",
        "cve": "CVE-2021-22145",
        "port": 9200,
        "service": "elasticsearch",
        "product": "Elasticsearch",
        "version": "7.13.x",
        "description": "Elasticsearch exposed on the public internet without authentication allows any attacker to read, modify, or delete all stored data. Hundreds of thousands of Elasticsearch instances have been compromised in large-scale data breach campaigns.",
        "remediation": "Enable X-Pack security in elasticsearch.yml. Bind Elasticsearch to 127.0.0.1 only. Use a reverse proxy with authentication in front of it. Block port 9200 at the firewall immediately."
    },
    11211: {
        "id": "SEC-MEMCACHED-01",
        "title": "Memcached Exposed — Reflection/Amplification DDoS Vector",
        "severity": "HIGH",
        "cve": "N/A - Configuration Issue",
        "port": 11211,
        "service": "memcached",
        "product": "Memcached",
        "version": "1.5.x",
        "description": "Publicly accessible Memcached servers can be weaponized as DDoS amplification vectors, generating up to 51,000x traffic amplification. Additionally, any data stored in Memcached is readable without authentication.",
        "remediation": "Immediately block port 11211 via firewall. Bind Memcached to loopback: `memcached -l 127.0.0.1`. Disable UDP support with `-U 0` to prevent amplification attacks."
    },
    27017: {
        "id": "CVE-2013-2132",
        "title": "MongoDB Unauthenticated Remote Access",
        "severity": "CRITICAL",
        "cve": "CVE-2013-2132",
        "port": 27017,
        "service": "mongodb",
        "product": "MongoDB",
        "version": "2.x / 3.x",
        "description": "MongoDB instances exposed without authentication allow any internet user to read, write, and delete all databases. Billions of records have been leaked through exposed MongoDB instances.",
        "remediation": "Enable MongoDB authentication (--auth flag). Bind to 127.0.0.1 only. Use role-based access control (RBAC). Block port 27017 at all public-facing firewalls."
    }
}

def get_service_name(port: int) -> str:
    port_to_service = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
        445: "microsoft-ds", 1433: "mssql", 3306: "mysql", 3389: "ms-wbt-server",
        5432: "postgresql", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"
    }
    return port_to_service.get(port, "unknown")

def generate_generic_vulnerability(port: int) -> dict:
    service = get_service_name(port)
    return {
        "id": f"GENERIC-PORT-{port}",
        "title": f"Exposed {service.upper()} Port {port}",
        "severity": "MEDIUM",
        "cve": "N/A - Port Exposure",
        "port": port,
        "service": service,
        "description": f"The port {port} running service '{service}' is open and exposed to the public internet. Exposing network services publicly increases the overall attack surface and risks potential brute-force or Zero-Day attacks.",
        "remediation": f"Verify if port {port} needs to be exposed to the public internet. If not, close the port at the firewall or bind it to localhost (127.0.0.1). If exposure is required, implement multi-factor authentication and strict access control lists (ACLs)."
    }

@app.get("/api/profiles")
def get_profiles():
    """Retrieve available mock business profiles for scanning"""
    profiles_summary = []
    for key, val in COMPANY_PROFILES.items():
        profiles_summary.append({
            "key": key,
            "name": val["name"],
            "description": val["description"],
            "target": val["recon"]["target"],
            "ip": val["recon"]["ip"]
        })
    return {"profiles": profiles_summary}

@app.post("/api/scan/custom")
def run_custom_scan_pipeline(payload: CustomScanPayload, request: Request):
    """Execute the multi-agent scanning and analysis pipeline on a custom target.
    Uses REAL network scanning when scanner module is available."""
    # 1. Rate Limiting Check
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not limiter.check_request(client_ip):
        raise HTTPException(
            status_code=429, 
            detail="Rate limit exceeded. Maximum 3 scans per 30 seconds. Please try again later."
        )

    # 2. Input Security Validation
    if not validate_ip(payload.ip):
        raise HTTPException(status_code=400, detail=f"Security Error: Invalid IP address syntax: '{payload.ip}'")
    if not validate_ports(payload.ports):
        raise HTTPException(status_code=400, detail="Security Error: Invalid port range or type. Ports must be integers 1-65535.")

    results = {}
    
    # ─── REAL SCANNING PATH ───
    if HAS_SCANNER:
        print(f"[REAL SCAN] Starting live scan for {payload.ip} ({payload.target})...")
        
        # Run the real scanner
        real_recon = full_recon_scan(
            ip=payload.ip,
            domain=payload.target if payload.target != payload.ip else None,
            ports=payload.ports,
            timeout=2.0
        )
        
        # Generate real vulnerabilities from open ports
        open_ports = real_recon.get("ports", [])
        real_vulnerabilities = _generate_real_vulnerabilities(open_ports, real_recon)
        
        # 1. Recon Agent (with real data)
        recon_result = pipeline.run_recon_agent("custom", real_scan_data=real_recon)
        results["recon"] = recon_result
        
        # 2. Vulnerability Agent (with real vulnerabilities)
        vuln_result = pipeline.run_vulnerability_agent(recon_result["data"], "custom", real_vulns=real_vulnerabilities)
        results["vulnerability"] = vuln_result
        
        # 3. Risk Analysis Agent
        risk_result = pipeline.run_risk_analysis_agent(
            payload.name, 
            recon_result["data"], 
            vuln_result["data"]
        )
        results["risk"] = risk_result
        
        # 4. Report Generation Agent
        report_result = pipeline.run_report_agent(
            payload.name, 
            payload.description, 
            recon_result["data"], 
            risk_result["data"]
        )
        results["report"] = report_result
        
        # 5. Comprehensive Recon Report (real data)
        comp_recon = generate_comprehensive_recon(
            payload.name, recon_result["data"], vuln_result["data"]
        )
        
        return {
            "status": "success",
            "scan_type": "REAL",
            "company_name": payload.name,
            "company_description": payload.description,
            "results": results,
            "comprehensive_recon": comp_recon
        }
    
    # ─── FALLBACK: SIMULATED PATH (same as before) ───
    # Only validate target domain syntax for simulated scans
    if not validate_target(payload.target):
        raise HTTPException(status_code=400, detail=f"Security Error: Invalid domain/target syntax: '{payload.target}'")
    
    ports_data = []
    vulnerabilities = []
    
    for port in payload.ports:
        service_name = get_service_name(port)
        if port in PORT_CVE_MAPPING:
            mapped_vuln = PORT_CVE_MAPPING[port]
            ports_data.append({
                "port": port,
                "service": service_name,
                "product": mapped_vuln["product"],
                "version": mapped_vuln["version"],
                "state": "open"
            })
            vulnerabilities.append(mapped_vuln)
        else:
            ports_data.append({
                "port": port,
                "service": service_name,
                "product": "generic-service",
                "version": "1.0",
                "state": "open"
            })
            vulnerabilities.append(generate_generic_vulnerability(port))
            
    custom_profile = {
        "name": payload.name,
        "description": payload.description,
        "recon": {
            "target": payload.target,
            "ip": payload.ip,
            "isp": "Custom Scan Gateway - AS13335 Cloudflare Inc.",
            "geo": "US-East (Virginia)",
            "ports": ports_data,
            "dns_records": {
                "A": payload.ip,
                "MX": f"mail.{payload.target} (Priority: 10)",
                "TXT": f"v=spf1 ip4:{payload.ip} ~all",
                "SPF": "SoftFail (~all) detected. Potentially allows spoofing.",
                "DMARC": "No valid _dmarc TXT record found."
            },
            "threat_intel": {
                "malware_score": "Low",
                "known_botnet": False,
                "spam_blocklist": "Clean"
            }
        },
        "vulnerabilities": vulnerabilities
    }
    
    # 1. Recon Agent
    recon_result = pipeline.run_recon_agent("custom", custom_profile=custom_profile)
    results["recon"] = recon_result
    
    # 2. Vulnerability Agent
    vuln_result = pipeline.run_vulnerability_agent(recon_result["data"], "custom", custom_profile=custom_profile)
    results["vulnerability"] = vuln_result
    
    # 3. Risk Analysis Agent
    risk_result = pipeline.run_risk_analysis_agent(
        payload.name, 
        recon_result["data"], 
        vuln_result["data"]
    )
    results["risk"] = risk_result
    
    # 4. Report Generation Agent
    report_result = pipeline.run_report_agent(
        payload.name, 
        payload.description, 
        recon_result["data"], 
        risk_result["data"]
    )
    results["report"] = report_result

    # 5. Comprehensive Recon Report
    comp_recon = generate_comprehensive_recon(
        payload.name, recon_result["data"], vuln_result["data"]
    )
    
    return {
        "status": "success",
        "scan_type": "SIMULATED",
        "company_name": payload.name,
        "company_description": payload.description,
        "results": results,
        "comprehensive_recon": comp_recon
    }


def _generate_real_vulnerabilities(open_ports: list, recon_data: dict) -> list:
    """Generate vulnerability findings based on real scan data (open ports + banners)."""
    vulnerabilities = []
    
    for port_info in open_ports:
        port = port_info["port"]
        service = port_info.get("service", "unknown")
        product = port_info.get("product", "unknown")
        version = port_info.get("version", "unknown")
        banner = port_info.get("banner", "")
        
        # Check against known CVE mapping first
        if port in PORT_CVE_MAPPING:
            vuln = PORT_CVE_MAPPING[port].copy()
            # Update with real detected product/version
            if product != "unknown":
                vuln["product"] = product
            if version != "unknown" and version != "detected":
                vuln["version"] = version
            vuln["description"] = f"[REAL SCAN] Port {port}/{service} is OPEN. Detected: {product} {version}. " + vuln["description"]
            vulnerabilities.append(vuln)
        else:
            # Generic vulnerability for open port
            severity = "LOW"
            if port in (23, 21, 445, 1433, 27017, 9200, 11211):
                severity = "HIGH"
            elif port in (3306, 5432, 6379, 3389):
                severity = "MEDIUM"
            
            vulnerabilities.append({
                "id": f"REAL-PORT-{port}",
                "title": f"Open {service.upper()} Port {port} Detected",
                "severity": severity,
                "cve": "N/A - Real Port Exposure",
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "description": f"[REAL SCAN] Port {port} running service '{service}' is confirmed OPEN via TCP connect scan. Detected product: {product} {version}. Banner: {banner[:100] if banner else 'No banner'}.",
                "remediation": f"Verify if port {port} ({service}) needs to be publicly accessible. If not, block it at the firewall. If required, ensure authentication and encryption are enforced."
            })
    
    # SSL/TLS vulnerabilities from real SSL check
    ssl_info = recon_data.get("ssl_info", {})
    if ssl_info and ssl_info.get("has_ssl"):
        tls_ver = ssl_info.get("tls_version", "")
        if "TLSv1.1" in tls_ver or "TLSv1" == tls_ver:
            vulnerabilities.append({
                "id": "REAL-SSL-OUTDATED",
                "title": f"Outdated TLS Protocol ({tls_ver}) Detected",
                "severity": "MEDIUM",
                "cve": "N/A - Protocol Issue",
                "port": 443,
                "service": "https",
                "description": f"[REAL SCAN] The server negotiated {tls_ver}, which is considered deprecated and vulnerable.",
                "remediation": "Configure the server to support only TLS 1.2 and TLS 1.3."
            })
        
        if ssl_info.get("is_expired"):
            vulnerabilities.append({
                "id": "REAL-SSL-EXPIRED",
                "title": "SSL Certificate EXPIRED",
                "severity": "CRITICAL",
                "cve": "N/A - Certificate Issue",
                "port": 443,
                "service": "https",
                "description": f"[REAL SCAN] The SSL certificate expired on {ssl_info.get('not_after', 'unknown')}. Browsers will show security warnings.",
                "remediation": "Renew the SSL certificate immediately."
            })
        elif ssl_info.get("days_until_expiry", 999) < 30 and ssl_info.get("days_until_expiry", 999) >= 0:
            vulnerabilities.append({
                "id": "REAL-SSL-EXPIRING",
                "title": f"SSL Certificate Expiring in {ssl_info['days_until_expiry']} Days",
                "severity": "LOW",
                "cve": "N/A - Certificate Issue",
                "port": 443,
                "service": "https",
                "description": f"[REAL SCAN] The SSL certificate will expire on {ssl_info.get('not_after', 'unknown')}.",
                "remediation": "Renew the SSL certificate before expiration."
            })
    
    # Security header vulnerabilities
    sec_headers = recon_data.get("security_headers", {})
    missing_critical = []
    for header_name in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]:
        header_data = sec_headers.get(header_name, {})
        if isinstance(header_data, dict) and header_data.get("status") == "Missing":
            missing_critical.append(header_name)
    
    if missing_critical:
        vulnerabilities.append({
            "id": "REAL-HEADERS-MISSING",
            "title": f"Critical Security Headers Missing ({len(missing_critical)})",
            "severity": "MEDIUM",
            "cve": "N/A - Configuration Issue",
            "port": 443,
            "service": "https",
            "description": f"[REAL SCAN] The following critical security headers are missing: {', '.join(missing_critical)}.",
            "remediation": f"Configure the web server to include: {', '.join(missing_critical)}."
        })
    
    return vulnerabilities

@app.get("/api/scan/{profile_key}")
def run_scan_pipeline(profile_key: str, request: Request):
    """Execute the multi-agent scanning and analysis pipeline"""
    # 1. Rate Limiting Check
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not limiter.check_request(client_ip):
        raise HTTPException(
            status_code=429, 
            detail="Rate limit exceeded. Maximum 3 scans per 30 seconds. Please try again later."
        )

    if profile_key not in COMPANY_PROFILES:
        raise HTTPException(status_code=404, detail="Company profile not found")
    
    profile = COMPANY_PROFILES[profile_key]
    results = {}
    
    # 1. Recon Agent
    recon_result = pipeline.run_recon_agent(profile_key)
    results["recon"] = recon_result
    
    # 2. Vulnerability Agent
    vuln_result = pipeline.run_vulnerability_agent(recon_result["data"], profile_key)
    results["vulnerability"] = vuln_result
    
    # 3. Risk Analysis Agent
    risk_result = pipeline.run_risk_analysis_agent(
        profile["name"], 
        recon_result["data"], 
        vuln_result["data"]
    )
    results["risk"] = risk_result
    
    # 4. Report Generation Agent
    report_result = pipeline.run_report_agent(
        profile["name"], 
        profile["description"], 
        recon_result["data"], 
        risk_result["data"]
    )
    results["report"] = report_result

    # 5. Comprehensive Recon Report
    comp_recon = generate_comprehensive_recon(
        profile["name"], recon_result["data"], vuln_result["data"]
    )
    
    return {
        "status": "success",
        "company_name": profile["name"],
        "company_description": profile["description"],
        "results": results,
        "comprehensive_recon": comp_recon
    }

# Mount frontend directory for hosting static client files
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
else:
    print(f"Warning: Frontend directory '{frontend_dir}' not found. API routes are active.")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
