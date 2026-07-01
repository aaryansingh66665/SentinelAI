import os
import json
import time
from agents.adk import Agent, Task, Workflow

# Import real scanner
try:
    from tools.scanner import full_recon_scan, real_ssl_check, real_http_headers, real_subdomain_scan, get_service_name as scanner_get_service
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False

# Attempt to import google-generativeai. If not available, we use local fallback model simulation.
try:
    import google.generativeai as genai
    HAS_GENAI = True
except ImportError:
    HAS_GENAI = False

# Mock Company Profile Templates
COMPANY_PROFILES = {
    "ecommerce": {
        "name": "Apex Footwear E-Commerce Store",
        "description": "A growing Shopify-integrated WooCommerce website handling online retail and customer accounts.",
        "recon": {
            "target": "shop.apexfootwear-demo.com",
            "ip": "104.244.42.1",
            "isp": "Cloudflare, Inc. - AS13335",
            "geo": "US-West (San Francisco)",
            "ports": [
                {"port": 80, "service": "http", "product": "nginx", "version": "1.18.0", "state": "open"},
                {"port": 443, "service": "https", "product": "nginx", "version": "1.18.0", "state": "open"},
                {"port": 22, "service": "ssh", "product": "OpenSSH", "version": "7.4p1 Debian 10+deb9u7", "state": "open"},
                {"port": 3306, "service": "mysql", "product": "MySQL", "version": "5.7.22", "state": "open"},
                {"port": 6379, "service": "redis", "product": "Redis key-value store", "version": "5.0.0", "state": "open"}
            ],
            "dns_records": {
                "A": "104.244.42.1",
                "MX": "mail.apexfootwear-demo.com (Priority: 10)",
                "TXT": "v=spf1 include:_spf.google.com ~all",
                "SPF": "SoftFail (~all) detected — spoofing possible from non-SPF sources.",
                "DMARC": "No valid _dmarc TXT record found — no email reject policy enforced."
            },
            "threat_intel": {
                "malware_score": "Low",
                "known_botnet": False,
                "spam_blocklist": "Listed on Spamhaus PBL"
            }
        },
        "vulnerabilities": [
            {
                "id": "CVE-2021-27928",
                "title": "MySQL Remote Code Execution via Extension Loading",
                "severity": "CRITICAL",
                "cve": "CVE-2021-27928",
                "port": 3306,
                "service": "mysql",
                "description": "The MariaDB/MySQL server allows remote authenticated users to trigger remote code execution by loading a shared library from a SQL query. Exposed port 3306 with default/weak credentials increases this risk significantly.",
                "remediation": "Do not expose MySQL port 3306 to the public internet. Bind it to localhost (127.0.0.1) or restrict access via firewall rules to specific trusted IPs. Upgrade database version to 5.7.34+ or 8.0.24+."
            },
            {
                "id": "CVE-2018-1311",
                "title": "Apache Xerces-C XML Parser Denial of Service",
                "severity": "MEDIUM",
                "cve": "CVE-2018-1311",
                "port": 80,
                "service": "http",
                "description": "An issue in Apache Xerces-C XML parser allows remote attackers to cause a denial of service (CPU consumption) via a crafted XML document.",
                "remediation": "Update libraries using Xerces-C to the latest secure version, or restrict HTTP upload sizes and parse settings."
            },
            {
                "id": "SEC-REDIS-01",
                "title": "Exposed Unauthenticated Redis Server",
                "severity": "HIGH",
                "cve": "N/A - Configuration Issue",
                "port": 6379,
                "service": "redis",
                "description": "The Redis key-value database is exposed to the public internet without password authentication. An attacker can execute arbitrary commands, read sensitive database contents, or write keys to write files on the server.",
                "remediation": "Enable password authentication in redis.conf (`requirepass`). Bind Redis to local interfaces only (`bind 127.0.0.1`). Use firewall rules to block port 6379 from WAN."
            },
            {
                "id": "CVE-2019-1589",
                "title": "SSH Weak Configuration / Outdated Version",
                "severity": "LOW",
                "cve": "CVE-2019-1589",
                "port": 22,
                "service": "ssh",
                "description": "The OpenSSH 7.4 server is outdated and configured to accept password-based authentication, increasing vulnerability to brute force attacks.",
                "remediation": "Disable password-based authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`) and enforce SSH key-based login. Upgrade OpenSSH to version 8.0+."
            }
        ]
    },
    "clinic": {
        "name": "Starlight Dental Clinic",
        "description": "A local dental clinic processing patient medical files, bookings, and billing histories.",
        "recon": {
            "target": "office.starlightdental.net",
            "ip": "203.0.113.84",
            "isp": "Comcast Cable Communications - AS7922",
            "geo": "US-East (Chicago, IL)",
            "ports": [
                {"port": 80, "service": "http", "product": "IIS", "version": "8.5", "state": "open"},
                {"port": 445, "service": "microsoft-ds", "product": "Windows SMB", "version": "Active Directory Domain", "state": "open"},
                {"port": 3389, "service": "ms-wbt-server", "product": "Microsoft Terminal Services (RDP)", "version": "Windows 8.1 / Server 2012 R2 RDP", "state": "open"}
            ],
            "dns_records": {
                "A": "203.0.113.84",
                "MX": "mail.starlightdental.net (Priority: 5)",
                "TXT": "v=spf1 ip4:203.0.113.84 -all",
                "SPF": "HardFail (-all) configured — good email spoofing protection.",
                "DMARC": "No valid _dmarc TXT record found — domain impersonation risk."
            },
            "threat_intel": {
                "malware_score": "Medium",
                "known_botnet": False,
                "spam_blocklist": "Clean"
            }
        },
        "vulnerabilities": [
            {
                "id": "CVE-2017-0144",
                "title": "MS17-010 EternalBlue Windows SMB Remote Code Execution",
                "severity": "CRITICAL",
                "cve": "CVE-2017-0144",
                "port": 445,
                "service": "microsoft-ds",
                "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets. This is famously exploited by WannaCry and NotPetya ransomwares.",
                "remediation": "Disable SMBv1 completely in Windows Features. Install MS17-010 security update. Immediately block port 445 at the network boundary firewall."
            },
            {
                "id": "CVE-2019-0708",
                "title": "BlueKeep Remote Desktop Protocol Remote Code Execution",
                "severity": "CRITICAL",
                "cve": "CVE-2019-0708",
                "port": 3389,
                "service": "ms-wbt-server",
                "description": "A remote code execution vulnerability exists in Remote Desktop Services (formerly known as Terminal Services) when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests.",
                "remediation": "Apply the BlueKeep security patch from Microsoft. Enforce Network Level Authentication (NLA) for RDP. Restrict RDP port 3389 via VPN and firewall rules."
            }
        ]
    },
    "accounting": {
        "name": "Vanguard Accounting Partners",
        "description": "A financial advisory and audit firm using a local server for test integrations and client dashboard previews.",
        "recon": {
            "target": "dev.vanguard-accounting.com",
            "ip": "198.51.100.12",
            "isp": "Verizon Business - AS701",
            "geo": "US-East (New York, NY)",
            "ports": [
                {"port": 443, "service": "https", "product": "Apache httpd", "version": "2.4.41", "state": "open"},
                {"port": 8080, "service": "http-proxy", "product": "Jenkins", "version": "2.121", "state": "open"}
            ],
            "dns_records": {
                "A": "198.51.100.12",
                "MX": "mx.vanguard-accounting.com (Priority: 10)",
                "TXT": "v=spf1 include:sendgrid.net ~all",
                "SPF": "SoftFail (~all) detected — phishing risk via email spoofing.",
                "DMARC": "v=DMARC1; p=quarantine — partial enforcement, some protection."
            },
            "threat_intel": {
                "malware_score": "Low",
                "known_botnet": False,
                "spam_blocklist": "Clean"
            }
        },
        "vulnerabilities": [
            {
                "id": "CVE-2018-1000861",
                "title": "Jenkins Remote Code Execution via Stapler web framework",
                "severity": "CRITICAL",
                "cve": "CVE-2018-1000861",
                "port": 8080,
                "service": "http-proxy",
                "description": "An improper accessibility check in the Stapler web framework of Jenkins allows unauthenticated remote attackers to execute arbitrary code via HTTP GET requests.",
                "remediation": "Upgrade Jenkins to LTS 2.150.1 or higher. Do not expose administrative CI/CD control portals to the public internet; place them behind a secure VPN or proxy configuration."
            },
            {
                "id": "SEC-SSL-01",
                "title": "SSL/TLS Outdated Protocol Configuration (TLS 1.0/1.1 Enabled)",
                "severity": "LOW",
                "cve": "N/A - Protocol Suite",
                "port": 443,
                "service": "https",
                "description": "The Apache server supports deprecated SSL versions TLS 1.0 and TLS 1.1, which contain cryptographic vulnerabilities that could allow interception of traffic.",
                "remediation": "Modify SSL settings to disable TLS 1.0 and 1.1. Restrict cipher configurations to TLS 1.2 and TLS 1.3 only."
            }
        ]
    }
}

# Local AI Fallback Simulator
def get_fallback_risk_analysis(company_name, recon_data, vulnerabilities):
    vuln_summary = ""
    for v in vulnerabilities:
        vuln_summary += f"- {v['title']} (Severity: {v['severity']}, Port: {v['port']})\n"
    
    analysis = {
        "risk_level": "CRITICAL" if any(v["severity"] == "CRITICAL" for v in vulnerabilities) else "HIGH",
        "business_impact": (
            f"The primary risks for {company_name} center on their exposed network services. "
            f"Specifically, the presence of {len(vulnerabilities)} vulnerabilities, some of which are classified as critical, "
            "represents a high probability of immediate system compromise if probed by automated scanner bots. "
            "A successful breach could lead to unauthorized system access, ransomware deployment, or client database theft."
        ),
        "priority_remediations": [
            "Implement a strict firewall policy blocking external traffic to non-public ports (e.g. databases, management services).",
            "Establish host-based firewalls and configure local interface bindings (127.0.0.1) for services that don't need external access.",
            "Run software updates immediately to patch known high/critical vulnerability CVEs.",
            "Enable VPN access for administrative actions such as SSH, RDP, or build server control dashboards."
        ]
    }
    return analysis

def get_fallback_executive_summary(company_name, description, recon_data, analysis):
    # Detect if this was a real or simulated scan
    scan_meta = recon_data.get("scan_metadata", {})
    is_real = scan_meta.get("scan_type") == "REAL"
    scan_type_label = "live network reconnaissance" if is_real else "simulated security evaluation"
    
    ports_list = recon_data.get('ports', [])
    port_str = ', '.join([str(p['port']) + '/' + p['service'] for p in ports_list]) if ports_list else 'None detected'
    
    geo_str = recon_data.get('geo', 'Unknown')
    isp_str = recon_data.get('isp', 'Unknown')
    
    summary_text = (
        f"# Cybersecurity Posture Assessment for {company_name}\n\n"
        f"**Date:** {time.strftime('%Y-%m-%d')}\n"
        f"**Target Host:** {recon_data['target']} ({recon_data['ip']})\n"
        f"**Location:** {geo_str}\n"
        f"**ISP:** {isp_str}\n"
        f"**Scan Type:** {'🔴 LIVE SCAN' if is_real else '🔵 Simulated'}\n"
        f"**Overall Risk Rating: {analysis['risk_level']}**\n\n"
    )
    
    if is_real:
        duration = scan_meta.get('scan_duration_seconds', 'N/A')
        ports_scanned = scan_meta.get('ports_scanned', 'N/A')
        ports_open = scan_meta.get('ports_open', 0)
        summary_text += (
            f"### Scan Statistics\n"
            f"- **Ports Scanned:** {ports_scanned}\n"
            f"- **Open Ports Found:** {ports_open}\n"
            f"- **Scan Duration:** {duration}s\n\n"
        )
    
    summary_text += (
        f"### Executive Overview\n"
        f"Sentinel AI has performed a {scan_type_label} of {company_name}. "
    )
    
    if is_real and len(ports_list) == 0:
        summary_text += (
            "No open ports were detected on the target. The target appears to have a strong "
            "perimeter firewall or is not actively running public services on the scanned ports.\n\n"
        )
    else:
        summary_text += (
            f"The system is currently configured with exposed ports that present substantial exposure vectors. "
            f"Based on the exposed endpoints, the organization is vulnerable to remote intrusion vectors.\n\n"
        )
    
    summary_text += (
        f"### Key Findings\n"
        f"- **Exposure Profile:** Exposed services include {port_str}.\n"
        f"- **Vulnerability Posture:** {analysis['business_impact']}\n\n"
        f"### Immediate Action Plan\n"
    )
    for i, step in enumerate(analysis["priority_remediations"], 1):
        summary_text += f"{i}. **{step}**\n"
    
    if is_real:
        summary_text += (
            "\n### Disclaimer\n"
            "This report is based on live network reconnaissance data. It does not constitute a full penetration test, "
            "but highlights real configuration gaps visible from the public Internet."
        )
    else:
        summary_text += (
            "\n### Disclaimer\n"
            "This report is a simulated security evaluation using pre-configured demo profiles. "
            "It highlights common configuration gaps for educational purposes."
        )
    return summary_text

# Gemini Agent Pipeline

# ─────────────────── Comprehensive Recon Helpers ───────────────────

def _increment_ip(ip_str, n):
    """Generate a neighbouring IP for subdomain simulation"""
    try:
        parts = ip_str.split('.')
        if len(parts) == 4:
            parts[3] = str((int(parts[3]) + n) % 254 + 1)
            return '.'.join(parts)
    except Exception:
        pass
    return ip_str


def _detect_tech_stack(ports):
    stack = {
        "web_server": "Unknown", "framework": "Not Detected",
        "backend": "Not Detected", "cms": "Not Detected",
        "cdn": "Not Detected", "database": "Not Detected", "libraries": []
    }
    libs = set()
    for p in ports:
        prod = p.get("product", "").lower()
        svc  = p.get("service", "").lower()
        if "nginx"  in prod: stack["web_server"] = "Nginx"; libs.add("OpenResty/Nginx Lua")
        elif "apache" in prod: stack["web_server"] = "Apache HTTPD"
        elif "iis" in prod: stack["web_server"] = "Microsoft IIS"; stack["backend"] = "ASP.NET"
        if "mysql"  in prod or svc == "mysql":
            stack["database"] = "MySQL"
            if stack["backend"] == "Not Detected": stack["backend"] = "PHP / Python"
            libs.add("PDO / MySQLi")
        elif "postgresql" in prod or svc == "postgresql": stack["database"] = "PostgreSQL"
        elif "mongodb" in prod or svc == "mongodb":
            stack["database"] = "MongoDB"
            if stack["backend"] == "Not Detected": stack["backend"] = "Node.js / Python"
        elif "redis" in prod or svc == "redis":
            if stack["database"] == "Not Detected": stack["database"] = "Redis (Cache Layer)"
        elif "elasticsearch" in prod or "elasticsearch" in svc:
            stack["database"] = "Elasticsearch"
            if stack["backend"] == "Not Detected": stack["backend"] = "Java / Python"
        if "jenkins" in prod: stack["framework"] = "Jenkins CI/CD"; stack["backend"] = "Java"
        if "cloudflare" in prod: stack["cdn"] = "Cloudflare"
    if any(p.get("service") in ("http", "https") for p in ports):
        libs.update(["jQuery 3.x", "Bootstrap 4/5"])
    if stack["web_server"] == "Nginx": libs.add("React / Vue (SPA, inferred)")
    stack["libraries"] = sorted(libs) if libs else ["None Detected"]
    return stack


def _generate_ssl_info(target, risk_level):
    from datetime import datetime, timedelta
    now = datetime.now()
    if risk_level == "CRITICAL":
        days, tls, weak = 8,  "TLS 1.0 / TLS 1.1 (deprecated)", True
    elif risk_level == "HIGH":
        days, tls, weak = 22, "TLS 1.1 / TLS 1.2", True
    else:
        days, tls, weak = 285, "TLS 1.2 / TLS 1.3", False
    expiry = now + timedelta(days=days)
    return {
        "issuer": "Let's Encrypt Authority X3", "subject": f"*.{target}",
        "valid_from": (now - timedelta(days=80)).strftime("%Y-%m-%d"),
        "valid_until": expiry.strftime("%Y-%m-%d"),
        "days_until_expiry": days, "tls_version": tls,
        "weak_ciphers_detected": weak, "certificate_valid": days > 0,
        "expiry_risk": "CRITICAL" if days < 14 else ("HIGH" if days < 30 else "LOW")
    }


def _generate_security_headers(risk_level):
    if risk_level == "CRITICAL":
        return {
            "Content-Security-Policy":   {"status": "Missing", "risk": "High"},
            "Strict-Transport-Security": {"status": "Missing", "risk": "High"},
            "X-Frame-Options":           {"status": "Missing", "risk": "Medium"},
            "X-Content-Type-Options":    {"status": "Missing", "risk": "Medium"},
            "Referrer-Policy":           {"status": "Missing", "risk": "Low"},
            "Permissions-Policy":        {"status": "Missing", "risk": "Low"},
        }
    elif risk_level == "HIGH":
        return {
            "Content-Security-Policy":   {"status": "Missing", "risk": "High"},
            "Strict-Transport-Security": {"status": "Present", "risk": "None"},
            "X-Frame-Options":           {"status": "Present", "risk": "None"},
            "X-Content-Type-Options":    {"status": "Missing", "risk": "Medium"},
            "Referrer-Policy":           {"status": "Present", "risk": "None"},
            "Permissions-Policy":        {"status": "Missing", "risk": "Low"},
        }
    else:
        return {
            "Content-Security-Policy":   {"status": "Present", "risk": "None"},
            "Strict-Transport-Security": {"status": "Present", "risk": "None"},
            "X-Frame-Options":           {"status": "Present", "risk": "None"},
            "X-Content-Type-Options":    {"status": "Present", "risk": "None"},
            "Referrer-Policy":           {"status": "Present", "risk": "None"},
            "Permissions-Policy":        {"status": "Missing", "risk": "Low"},
        }


def _detect_cloud_provider(ip, isp):
    isp_l = isp.lower()
    if "cloudflare" in isp_l:   provider, cdn, exp = "Cloudflare",                    "Cloudflare CDN",        "Low"
    elif "amazon" in isp_l or "aws" in isp_l:
                                 provider, cdn, exp = "Amazon Web Services (AWS)",    "Amazon CloudFront",     "Medium"
    elif "google" in isp_l or "gcp" in isp_l:
                                 provider, cdn, exp = "Google Cloud Platform (GCP)",  "Google Cloud CDN",      "Medium"
    elif "microsoft" in isp_l or "azure" in isp_l:
                                 provider, cdn, exp = "Microsoft Azure",              "Azure CDN",             "Medium"
    elif "digitalocean" in isp_l: provider, cdn, exp = "DigitalOcean",               "None Detected",         "High"
    elif "linode" in isp_l or "akamai" in isp_l:
                                 provider, cdn, exp = "Linode / Akamai",             "Akamai CDN",            "Medium"
    elif "comcast" in isp_l:     provider, cdn, exp = "On-Premise (Comcast Business)","None Detected",        "High"
    elif "verizon" in isp_l:     provider, cdn, exp = "On-Premise (Verizon Business)","None Detected",        "High"
    else:                        provider, cdn, exp = "Unknown / On-Premise",        "None Detected",         "High"
    storage = ["Public cloud storage detected — S3/Blob bucket enumeration recommended"] \
              if any(x in provider for x in ["AWS", "Azure", "GCP"]) else []
    return {"provider": provider, "cdn": cdn, "storage_exposure": storage,
            "exposure_rating": exp, "shodan_score": "Low" if exp == "Low" else "Medium"}


def generate_comprehensive_recon(profile_name, recon_data, vulnerabilities):
    """Generate a full professional website reconnaissance report dataset.
    Uses real data from scanner when available, falls back to simulated data."""
    import time as _time
    target = recon_data.get("target", "unknown.com")
    ip     = recon_data.get("ip", "0.0.0.0")
    isp    = recon_data.get("isp", "")
    dns    = recon_data.get("dns_records", {})
    ports  = recon_data.get("ports", [])
    scan_meta = recon_data.get("scan_metadata", {})
    is_real = scan_meta.get("scan_type") == "REAL"

    c  = sum(1 for v in vulnerabilities if v.get("severity") == "CRITICAL")
    h  = sum(1 for v in vulnerabilities if v.get("severity") == "HIGH")
    m  = sum(1 for v in vulnerabilities if v.get("severity") == "MEDIUM")
    lo = sum(1 for v in vulnerabilities if v.get("severity") == "LOW")
    overall_risk = "CRITICAL" if c > 0 else ("HIGH" if h > 0 else ("MEDIUM" if m > 0 else "LOW"))

    parts = target.split(".")
    base  = ".".join(parts[-2:]) if len(parts) >= 2 else target

    # Use real subdomains if available from scanner, otherwise generate mock
    if is_real and recon_data.get("subdomains"):
        subdomains = recon_data["subdomains"]
    else:
        subdomains = [
            {"subdomain": f"www.{base}",     "status": "Active",   "ip": ip,                    "risk": "Low"},
            {"subdomain": f"mail.{base}",    "status": "Active",   "ip": _increment_ip(ip,1),   "risk": "Low"},
            {"subdomain": f"api.{base}",     "status": "Active",   "ip": ip,                    "risk": "Medium"},
            {"subdomain": f"dev.{base}",     "status": "Active",   "ip": _increment_ip(ip,5),   "risk": "High"},
            {"subdomain": f"staging.{base}", "status": "Active",   "ip": _increment_ip(ip,6),   "risk": "High"},
            {"subdomain": f"admin.{base}",   "status": "Active",   "ip": ip,                    "risk": "Critical"},
            {"subdomain": f"cdn.{base}",     "status": "Active",   "ip": _increment_ip(ip,10),  "risk": "Low"},
            {"subdomain": f"vpn.{base}",     "status": "Active",   "ip": _increment_ip(ip,3),   "risk": "Medium"},
            {"subdomain": f"ftp.{base}",     "status": "Inactive", "ip": "N/A",                 "risk": "Low"},
        ]

    # Use real SSL/headers if available from scanner, otherwise generate simulated
    if is_real and recon_data.get("ssl_info"):
        ssl = recon_data["ssl_info"]
        # Ensure ssl has required keys for scoring
        if "tls_version" not in ssl:
            ssl["tls_version"] = "N/A"
        if "days_until_expiry" not in ssl:
            ssl["days_until_expiry"] = -1
    else:
        ssl = _generate_ssl_info(target, overall_risk)
    
    if is_real and recon_data.get("security_headers"):
        headers = recon_data["security_headers"]
    else:
        headers = _generate_security_headers(overall_risk)

    tech    = _detect_tech_stack(ports)
    cloud   = _detect_cloud_provider(ip, isp)

    # SPF/DMARC detection from real DNS data
    spf_val = dns.get("SPF", "")
    dmarc_val = dns.get("DMARC", "")
    has_spf   = bool(spf_val and "No " not in spf_val and "N/A" not in spf_val)
    has_dmarc = bool(dmarc_val and "No " not in dmarc_val and "N/A" not in dmarc_val)
    
    # Filter only dict-type header values for scoring
    headers_ok = sum(1 for k, hv in headers.items() if isinstance(hv, dict) and hv.get("status") == "Present")

    dns_score = min(10, 4 + (3 if has_spf else 0) + (3 if has_dmarc else 0))
    
    tls_ver = ssl.get("tls_version", "N/A") if isinstance(ssl, dict) else "N/A"
    days_exp = ssl.get("days_until_expiry", -1) if isinstance(ssl, dict) else -1
    ssl_score = 9 if "TLS 1.3" in str(tls_ver) else (6 if "TLS 1.2" in str(tls_ver) else 3)
    ssl_score = max(1, ssl_score - (4 if days_exp < 14 and days_exp >= 0 else (2 if days_exp < 30 and days_exp >= 0 else 0)))
    
    web_score = max(1, min(10, headers_ok * 2 - c * 3))
    exp_score = max(1, 10 - len(ports) + 2)
    overall_score = int((dns_score + ssl_score + web_score + exp_score) / 4 * 10)

    # GeoIP from real data
    geo_details = recon_data.get("geo_details", {})
    geo_country = geo_details.get("country", "United States") if geo_details else "United States"
    
    # WHOIS — use real NS from DNS if available
    ns_list = dns.get("NS", [f"ns1.{base}", f"ns2.{base}"])
    if isinstance(ns_list, str):
        ns_list = [ns_list]

    return {
        "overall_risk": overall_risk, "total_open_ports": len(ports),
        "total_subdomains": sum(1 for s in subdomains if s.get("status") == "Active"),
        "high_risk_findings": c + h, "assessment_date": _time.strftime("%Y-%m-%d"),
        "scan_type": "REAL" if is_real else "SIMULATED",
        "whois": {
            "organization": profile_name, "registrar": "NameCheap, Inc.",
            "registration_date": "2019-03-15", "expiration_date": "2027-03-15",
            "name_servers": ns_list[:4], "country": geo_country,
            "contact": f"admin@{base}"
        },
        "subdomains": subdomains, "tech_stack": tech, "ssl_info": ssl,
        "security_headers": headers, "cloud_info": cloud,
        "severity_breakdown": {"CRITICAL": c, "HIGH": h, "MEDIUM": m, "LOW": lo},
        "attack_surface": {
            "dns_security": dns_score, "ssl_security": ssl_score,
            "web_security": web_score, "exposure_risk": exp_score,
            "overall_score": overall_score
        },
        "email_security": {
            "spf":   {"status": "Pass" if has_spf   else "Fail", "record": dns.get("TXT",   "Not Found")},
            "dkim":  {"status": "Unknown", "record": "Live DNS lookup required for DKIM verification"},
            "dmarc": {"status": "Pass" if has_dmarc else "Fail", "record": dmarc_val or "Not Found"},
            "email_spoofing_risk": "Low" if (has_spf and has_dmarc) else "High",
            "phishing_exposure":   "Reduced" if has_dmarc else "Elevated"
        },
        "shodan_intelligence": {
            "open_services": len(ports), "geolocation": recon_data.get("geo", "Unknown"),
            "isp": isp, "exposure_rating": cloud["exposure_rating"],
            "shodan_score": cloud["shodan_score"],
            "historical_data": scan_meta.get("scan_timestamp", "N/A") if is_real else "First seen: 2022-01-15 | Last indexed: 2026-06-01"
        },
        "scan_metadata": scan_meta
    }


class SentinelAgentPipeline:
    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY")
        self.model = "gemini-1.5-flash"
        
        # Instantiate ADK agents
        self.recon_agent = Agent(
            name="Recon Agent",
            role="Reconnaissance Specialist",
            system_instruction="You are a reconnaissance agent. Your task is to query public records and port scanners to identify the network footprint of a target organization.",
            model_name=self.model,
            api_key=self.api_key
        )
        self.vuln_agent = Agent(
            name="Vulnerability Agent",
            role="Vulnerability Analyst",
            system_instruction="You are a vulnerability analysis agent. Your job is to match discovered network ports to known vulnerabilities and configuration weaknesses.",
            model_name=self.model,
            api_key=self.api_key
        )
        self.risk_agent = Agent(
            name="Risk Analysis Agent",
            role="Risk Evaluator",
            system_instruction=(
                "You are a cybersecurity risk evaluation agent. Analyze the business context and vulnerability footprint to calculate "
                "a risk level (CRITICAL, HIGH, MEDIUM, or LOW), business impact description, and 4 priority remediations. "
                "Ensure your output is a valid JSON only containing the fields: risk_level, business_impact, priority_remediations."
            ),
            model_name=self.model,
            api_key=self.api_key
        )
        self.report_agent = Agent(
            name="Report Agent",
            role="Technical Writer",
            system_instruction=(
                "You are an executive security reporter. Formulate a professional executive cybersecurity report in Markdown "
                "based on the provided network footprint and risk analysis. Make it readable, polished, and structured. "
                "Do not include boilerplate disclaimers."
            ),
            model_name=self.model,
            api_key=self.api_key
        )

    def run_recon_agent(self, company_key, custom_profile=None, real_scan_data=None):
        """Recon Agent: Uses real scanner for custom scans, mock profiles for demos."""
        # If real scan data was provided (from scanner.py), use it directly
        if real_scan_data:
            recon_data = real_scan_data
            target = recon_data.get("target", "unknown")
            ip = recon_data.get("ip", "unknown")
            open_count = len(recon_data.get("ports", []))
            
            def recon_tool(prompt, context):
                return recon_data
            
            self.recon_agent.tools = [recon_tool]
            task = Task(
                name="Recon Task",
                agent=self.recon_agent,
                instruction=f"Live scan completed for {target} ({ip}). Found {open_count} open ports. DNS and GeoIP data collected."
            )
            res = task.execute(context={})
            return {
                "status": "success",
                "agent": "Recon Agent",
                "log": f"Live reconnaissance scan completed for {target} ({ip}). Found {open_count} open ports.",
                "data": res["data"]
            }
        
        # Fallback to mock profile
        profile = custom_profile or COMPANY_PROFILES.get(company_key)
        if not profile:
            raise ValueError("Unknown company profile")
            
        def recon_tool(prompt, context):
            return profile["recon"]

        self.recon_agent.tools = [recon_tool]
        
        task = Task(
            name="Recon Task",
            agent=self.recon_agent,
            instruction=f"Run Shodan scan for {profile['recon']['target']}... Discovered host {profile['recon']['ip']}. Querying DNS..."
        )
        
        res = task.execute(context={})
        return {
            "status": "success",
            "agent": "Recon Agent",
            "log": f"Running Shodan scan for {profile['recon']['target']}... Discovered host {profile['recon']['ip']}. Querying DNS...",
            "data": res["data"]
        }

    def run_vulnerability_agent(self, recon_data, company_key, custom_profile=None, real_vulns=None):
        """Vulnerability Agent: Maps discovered ports to potential CVEs and config exposures.
        Uses real vulnerability assessment for live scans."""
        
        # If real vulnerabilities were generated from scanner data, use them
        if real_vulns is not None:
            def vuln_tool(prompt, context):
                return real_vulns
            
            self.vuln_agent.tools = [vuln_tool]
            task = Task(
                name="Vulnerability Task",
                agent=self.vuln_agent,
                instruction=f"Analyzing {len(recon_data.get('ports', []))} open ports from live scan for vulnerabilities..."
            )
            res = task.execute(context=recon_data)
            return {
                "status": "success",
                "agent": "Vulnerability Agent",
                "log": f"Live vulnerability analysis completed. {len(real_vulns)} findings from real scan data.",
                "data": res["data"]
            }
        
        # Fallback to mock profile
        profile = custom_profile or COMPANY_PROFILES.get(company_key)
        if not profile:
            raise ValueError("Unknown company profile")
            
        def vuln_tool(prompt, context):
            return profile["vulnerabilities"]

        self.vuln_agent.tools = [vuln_tool]
        
        task = Task(
            name="Vulnerability Task",
            agent=self.vuln_agent,
            instruction=f"Analyzing {len(recon_data['ports'])} ports for matching CVEs and configuration issues..."
        )
        
        res = task.execute(context=recon_data)
        return {
            "status": "success",
            "agent": "Vulnerability Agent",
            "log": f"Analyzing {len(recon_data['ports'])} ports for matching CVEs and configuration issues...",
            "data": res["data"]
        }

    def run_risk_analysis_agent(self, company_name, recon_data, vulnerabilities):
        """Risk Analysis Agent: Analyzes the business context and calculates priority mitigations"""
        def risk_tool(prompt, context):
            return get_fallback_risk_analysis(company_name, recon_data, vulnerabilities)
            
        self.risk_agent.tools = [risk_tool]
        
        prompt = (
            f"Perform a professional security risk analysis for the business '{company_name}'.\n"
            f"Here is their exposure profile:\n{json.dumps(recon_data, indent=2)}\n\n"
            f"Here are the vulnerabilities found:\n{json.dumps(vulnerabilities, indent=2)}\n\n"
            "Provide a JSON response containing:\n"
            "1. 'risk_level': (CRITICAL, HIGH, MEDIUM, or LOW)\n"
            "2. 'business_impact': (A detailed paragraph on what these findings mean for the company's daily operations)\n"
            "3. 'priority_remediations': (A list of 4 clear, action-oriented, and realistic security actions they must take immediately)\n"
            "Ensure your output is valid JSON only."
        )
        
        task = Task(
            name="Risk Task",
            agent=self.risk_agent,
            instruction=prompt
        )
        
        res = task.execute(context={"recon": recon_data, "vulnerabilities": vulnerabilities})
        
        log_msg = "Risk assessment completed successfully using Gemini." if self.risk_agent.client else "Risk assessment generated via rule-based security parser (Gemini API unavailable)."
        
        return {
            "status": "success",
            "agent": "Risk Analysis Agent",
            "log": log_msg,
            "data": res["data"]
        }

    def run_report_agent(self, company_name, company_description, recon_data, analysis_data):
        """Report Generation Agent: Formulates an executive cybersecurity report in Markdown"""
        def report_tool(prompt, context):
            return get_fallback_executive_summary(company_name, company_description, recon_data, analysis_data)
            
        self.report_agent.tools = [report_tool]
        
        prompt = (
            f"Generate a professional executive cybersecurity report for '{company_name}' ({company_description}).\n"
            f"Exposure profile: {json.dumps(recon_data, indent=2)}\n"
            f"Risk Analysis: {json.dumps(analysis_data, indent=2)}\n\n"
            "Draft an executive report in clean Markdown. Include header details, a high-level overview of "
            "current risks, key vulnerability findings, and an immediate step-by-step remediation plan. "
            "Make it readable, polished, and structured. Do not include boilerplate disclaimers other than a "
            "standard system advisory warning."
        )
        
        task = Task(
            name="Report Task",
            agent=self.report_agent,
            instruction=prompt
        )
        
        res = task.execute(context={"recon": recon_data, "analysis": analysis_data})
        
        log_msg = "Executive summary report generated using Gemini." if self.report_agent.client else "Executive report drafted via local document builder (Gemini API unavailable)."
        
        # Handle cases where report_markdown might be directly returned as dict from tools or string
        report_text = res["data"]
        if isinstance(report_text, dict) and "report_markdown" in report_text:
            report_text = report_text["report_markdown"]
        elif isinstance(report_text, dict):
            report_text = json.dumps(report_text)
            
        return {
            "status": "success",
            "agent": "Report Generation Agent",
            "log": log_msg,
            "data": {"report_markdown": report_text}
        }
