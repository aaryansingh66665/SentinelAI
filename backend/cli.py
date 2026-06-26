import os
import sys
import json
import argparse
import getpass

# Add parent directory to path to ensure imports work
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agents.agents import CyberGuardAgentPipeline, COMPANY_PROFILES, generate_comprehensive_recon
from tools.security import encrypt_data, decrypt_data, validate_target, validate_ip, validate_ports

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


def handle_set_key():
    print("=== Secure API Key Configuration ===")
    api_key = input("Enter your GEMINI_API_KEY: ").strip()
    if not api_key:
        print("Error: API Key cannot be empty.")
        return
        
    passphrase = getpass.getpass("Enter a password to encrypt this key: ").strip()
    if not passphrase:
        print("Error: Encryption password cannot be empty.")
        return
        
    try:
        encrypted = encrypt_data(api_key, passphrase)
        
        # Write to .env.enc (one level up, in the project root)
        enc_file_path = os.path.join(os.path.dirname(__file__), "..", ".env.enc")
        with open(enc_file_path, "w") as f:
            f.write(encrypted)
            
        print(f"\n[SUCCESS] Encrypted API key saved securely to {os.path.basename(enc_file_path)}")
        print("To run scans using this key, you must set the environment variable DECRYPTION_PASSWORD before starting the app.")
    except Exception as e:
        print(f"Error encrypting key: {e}")


def handle_scan(args):
    # Attempt to load key
    api_key = os.environ.get("GEMINI_API_KEY")
    
    enc_file_path = os.path.join(os.path.dirname(__file__), "..", ".env.enc")
    if not api_key and os.path.exists(enc_file_path):
        passphrase = os.environ.get("DECRYPTION_PASSWORD")
        if not passphrase:
            print("[INFO] Encrypted API key detected (.env.enc).")
            passphrase = getpass.getpass("Enter password to decrypt the API Key: ").strip()
            
        try:
            with open(enc_file_path, "r") as f:
                encrypted_content = f.read().strip()
            api_key = decrypt_data(encrypted_content, passphrase)
            os.environ["GEMINI_API_KEY"] = api_key
            print("[SECURITY] Key decrypted and loaded successfully.")
        except Exception as e:
            print(f"[WARNING] Key decryption failed: {e}. Running in simulation/fallback mode.")
            
    # Initializing Agent Pipeline
    pipeline = CyberGuardAgentPipeline(api_key=api_key)
    
    profile_data = None
    
    # 1. Run profile scan
    if args.profile:
        profile_key = args.profile
        if profile_key not in COMPANY_PROFILES:
            print(f"Error: Unknown profile '{profile_key}'. Choose from: {list(COMPANY_PROFILES.keys())}")
            return
            
        profile = COMPANY_PROFILES[profile_key]
        print(f"Starting Multi-Agent Scan for business profile: '{profile['name']}'...")
        
        recon_res = pipeline.run_recon_agent(profile_key)
        vuln_res = pipeline.run_vulnerability_agent(recon_res["data"], profile_key)
        risk_res = pipeline.run_risk_analysis_agent(profile["name"], recon_res["data"], vuln_res["data"])
        report_res = pipeline.run_report_agent(profile["name"], profile["description"], recon_res["data"], risk_res["data"])
        
    # 2. Run custom scan
    else:
        if not args.name or not args.target or not args.ip or not args.ports:
            print("Error: For custom scans, you must provide --name, --target, --ip, and --ports.")
            return
            
        # Parse ports
        try:
            ports_list = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("Error: Ports must be a comma-separated list of integers (e.g. 22,80,443)")
            return
            
        # Validate inputs
        if not validate_target(args.target):
            print(f"Error: Target domain syntax '{args.target}' is invalid or insecure.")
            return
        if not validate_ip(args.ip):
            print(f"Error: Target IP address syntax '{args.ip}' is invalid.")
            return
        if not validate_ports(ports_list):
            print(f"Error: Ports must be in the range 1-65535.")
            return
            
        print(f"Starting Custom Multi-Agent Scan for target: {args.target} ({args.ip})...")
        
        ports_data = []
        vulnerabilities = []
        
        for port in ports_list:
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
            "name": args.name,
            "description": args.desc or "Custom Scan Gateway",
            "recon": {
                "target": args.target,
                "ip": args.ip,
                "isp": "Custom Scan Gateway - CLI",
                "geo": "US-East (CLI)",
                "ports": ports_data,
                "dns_records": {
                    "A": args.ip,
                    "MX": f"mail.{args.target}",
                    "TXT": f"v=spf1 ip4:{args.ip} ~all",
                    "SPF": "SoftFail (~all) detected",
                    "DMARC": "No valid _dmarc TXT record found"
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
        risk_res = pipeline.run_risk_analysis_agent(args.name, recon_res["data"], vuln_res["data"])
        report_res = pipeline.run_report_agent(args.name, args.desc or "", recon_res["data"], risk_res["data"])
        
    # Print results or save to file
    report_md = report_res["data"]["report_markdown"]
    
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(report_md)
            print(f"\n[SUCCESS] Executive report exported to file: {args.output}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("\n" + "="*40 + " ASSESSMENT REPORT " + "="*40)
        print(report_md)
        print("="*99)


def main():
    parser = argparse.ArgumentParser(description="CyberGuard AI CLI Agent - Multi-Agent Cybersecurity Scanner")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")
    
    # Subcommand: set-key
    subparsers.add_parser("set-key", help="Encrypt and save GEMINI_API_KEY to .env.enc")
    
    # Subcommand: scan
    scan_parser = subparsers.add_parser("scan", help="Run a security scan on a target")
    scan_parser.add_argument("--profile", type=str, choices=list(COMPANY_PROFILES.keys()), help="Name of the pre-configured company profile")
    scan_parser.add_argument("--name", type=str, help="Name of custom asset/business")
    scan_parser.add_argument("--target", type=str, help="Custom target domain/host (e.g. site.com)")
    scan_parser.add_argument("--ip", type=str, help="Custom target IP address")
    scan_parser.add_argument("--ports", type=str, help="Comma-separated custom ports to scan (e.g. 22,80,443)")
    scan_parser.add_argument("--desc", type=str, help="Optional description of the custom asset")
    scan_parser.add_argument("--output", type=str, help="Export assessment report markdown to file path")
    
    args = parser.parse_args()
    
    if args.command == "set-key":
        handle_set_key()
    elif args.command == "scan":
        handle_scan(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
