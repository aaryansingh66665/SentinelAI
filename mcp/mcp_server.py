import os
import json
from mcp.server.fastmcp import FastMCP

# Add parent directory to path to ensure imports work when run as standalone
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.agents import SentinelAgentPipeline, COMPANY_PROFILES, generate_comprehensive_recon
from tools.security import validate_target, validate_ip, validate_ports

# Import real scanner
try:
    from tools.scanner import full_recon_scan, get_service_name as scanner_get_service
    # Need to import _generate_real_vulnerabilities from app or duplicate logic. 
    # Better to import from app.
    from app import _generate_real_vulnerabilities
    HAS_SCANNER = True
except ImportError:
    HAS_SCANNER = False

# Initialize FastMCP Server
mcp = FastMCP("SentinelAI Security Scanner")

# Initialize Pipeline
pipeline = SentinelAgentPipeline()

# Standard service name resolver (copied/adapted from main.py to remain independent)
def get_service_name(port: int) -> str:
    port_to_service = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
        445: "microsoft-ds", 1433: "mssql", 3306: "mysql", 3389: "ms-wbt-server",
        5432: "postgresql", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
        9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"
    }
    return port_to_service.get(port, "unknown")

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
        "description": "The SSH server is outdated and configured to accept password-based authentication.",
        "remediation": "Disable password-based authentication in sshd_config and enforce SSH key-based login."
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
        "description": "An issue in Apache Xerces-C XML parser allows remote attackers to cause a denial of service.",
        "remediation": "Update libraries using Xerces-C to the latest secure version."
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
        "description": "The server supports deprecated SSL versions TLS 1.0 and TLS 1.1.",
        "remediation": "Modify SSL settings to disable TLS 1.0 and 1.1. Restrict ciphers to TLS 1.2 and 1.3."
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
        "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code.",
        "remediation": "Disable SMBv1 completely in Windows Features. Install MS17-010 security update."
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
        "description": "The MariaDB/MySQL server allows remote authenticated users to trigger remote code execution.",
        "remediation": "Do not expose MySQL port 3306. Bind it to localhost or restrict access via firewall."
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
        "description": "A remote code execution vulnerability exists in Remote Desktop Services.",
        "remediation": "Apply the BlueKeep security patch from Microsoft. Enforce Network Level Authentication."
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
        "description": "The Redis key-value database is exposed to the public internet without password authentication.",
        "remediation": "Enable password authentication in redis.conf (`requirepass`). Bind Redis to local interfaces only."
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
        "description": "An improper accessibility check in the Stapler web framework of Jenkins allows unauthenticated remote attackers to execute arbitrary code.",
        "remediation": "Upgrade Jenkins to LTS 2.150.1 or higher. Do not expose administrative CI/CD control portals."
    }
}

def generate_generic_vulnerability(port: int) -> dict:
    service = get_service_name(port)
    return {
        "id": f"GENERIC-PORT-{port}",
        "title": f"Exposed {service.upper()} Port {port}",
        "severity": "MEDIUM",
        "cve": "N/A - Port Exposure",
        "port": port,
        "service": service,
        "description": f"The port {port} running service '{service}' is open and exposed to the public internet.",
        "remediation": f"Verify if port {port} needs to be exposed. If not, close the port at the firewall."
    }

@mcp.tool()
def get_company_profiles() -> str:
    """Retrieve list of available mock profiles for small business network scans."""
    profiles = []
    for key, val in COMPANY_PROFILES.items():
        profiles.append({
            "key": key,
            "name": val["name"],
            "description": val["description"],
            "target": val["recon"]["target"],
            "ip": val["recon"]["ip"]
        })
    return json.dumps(profiles, indent=2)

@mcp.tool()
def run_security_scan(profile_key: str) -> str:
    """
    Run a multi-agent security posture scan on a mock small business profile.
    Args:
        profile_key (str): The profile key (e.g. 'ecommerce', 'clinic', 'accounting')
    """
    if profile_key not in COMPANY_PROFILES:
        return f"Error: Profile key '{profile_key}' not found. Available keys: {list(COMPANY_PROFILES.keys())}"
        
    profile = COMPANY_PROFILES[profile_key]
    
    recon_res = pipeline.run_recon_agent(profile_key)
    vuln_res = pipeline.run_vulnerability_agent(recon_res["data"], profile_key)
    risk_res = pipeline.run_risk_analysis_agent(profile["name"], recon_res["data"], vuln_res["data"])
    report_res = pipeline.run_report_agent(profile["name"], profile["description"], recon_res["data"], risk_res["data"])
    
    report_md = report_res["data"]["report_markdown"]
    return report_md

@mcp.tool()
def run_custom_security_scan(
    name: str,
    target: str,
    ip: str,
    ports: list[int],
    description: str = "Custom Scan Target"
) -> str:
    """
    Run a custom multi-agent security posture scan on a custom target.
    Args:
        name (str): Custom business/asset name
        target (str): Target domain or hostname (e.g. 'shop.mybusiness.com')
        ip (str): Target IP Address (e.g. '192.168.1.15')
        ports (list[int]): List of ports to probe (e.g. [22, 80, 443])
        description (str): Description of the asset
    """
    # ─── REAL SCANNING PATH ───
    if HAS_SCANNER:
        # Run the real scanner
        real_recon = full_recon_scan(
            ip=ip,
            domain=target if target != ip else None,
            ports=ports,
            timeout=2.0
        )
        
        open_ports = real_recon.get("ports", [])
        real_vulnerabilities = _generate_real_vulnerabilities(open_ports, real_recon)
        
        recon_res = pipeline.run_recon_agent("custom", real_scan_data=real_recon)
        vuln_res = pipeline.run_vulnerability_agent(recon_res["data"], "custom", real_vulns=real_vulnerabilities)
        risk_res = pipeline.run_risk_analysis_agent(name, recon_res["data"], vuln_res["data"])
        report_res = pipeline.run_report_agent(name, description, recon_res["data"], risk_res["data"])
        
        report_md = report_res["data"]["report_markdown"]
        return report_md

    # ─── FALLBACK: SIMULATED PATH ───
    # Only validate target domain syntax for simulated scans
    if not validate_target(target):
        return f"Security Error: Invalid domain/target syntax '{target}'."
        
    ports_data = []
    vulnerabilities = []
    
    for port in ports:
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
        "name": name,
        "description": description,
        "recon": {
            "target": target,
            "ip": ip,
            "isp": "Custom Gateway - AS13335",
            "geo": "US-East (Virginia)",
            "ports": ports_data,
            "dns_records": {
                "A": ip,
                "MX": f"mail.{target}",
                "TXT": f"v=spf1 ip4:{ip} ~all",
                "SPF": "SoftFail (~all) detected",
                "DMARC": "No DMARC record found"
            },
            "threat_intel": {
                "malware_score": "Low",
                "known_botnet": False,
                "spam_blocklist": "Clean"
            }
        },
        "vulnerabilities": vulnerabilities
    }
    
    recon_res = pipeline.run_recon_agent("custom", custom_profile=custom_profile)
    vuln_res = pipeline.run_vulnerability_agent(recon_res["data"], "custom", custom_profile=custom_profile)
    risk_res = pipeline.run_risk_analysis_agent(name, recon_res["data"], vuln_res["data"])
    report_res = pipeline.run_report_agent(name, description, recon_res["data"], risk_res["data"])
    
    report_md = report_res["data"]["report_markdown"]
    return report_md

if __name__ == "__main__":
    mcp.run()
