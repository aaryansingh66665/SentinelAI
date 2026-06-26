"""
scanner.py — Real Network Reconnaissance Module for CyberGuard AI

Performs actual network scanning using Python standard library + lightweight packages.
No Shodan API key or nmap required.

WARNING: Only scan targets you own or have explicit authorization to scan.
"""

import socket
import ssl
import struct
import time
import json
import concurrent.futures
from typing import List, Dict, Any, Optional
from datetime import datetime

# Optional imports with fallback
try:
    import dns.resolver
    import dns.exception
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ─────────────────── Port-to-Service Mapping ───────────────────

PORT_SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 389: "ldap", 443: "https",
    445: "microsoft-ds", 1433: "mssql", 3306: "mysql", 3389: "ms-wbt-server",
    5432: "postgresql", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb"
}

def get_service_name(port: int) -> str:
    return PORT_SERVICE_MAP.get(port, "unknown")


# ─────────────────── TCP Port Scanning ───────────────────

def scan_single_port(ip: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Perform a real TCP connect scan on a single port."""
    result = {
        "port": port,
        "service": get_service_name(port),
        "state": "closed",
        "product": "unknown",
        "version": "unknown",
        "banner": ""
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn_result = sock.connect_ex((ip, port))
        
        if conn_result == 0:
            result["state"] = "open"
            # Try banner grab
            try:
                # For HTTP ports, send a request
                if port in (80, 8080, 8443):
                    sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
                elif port == 443:
                    pass  # SSL handled separately
                else:
                    # Generic: wait for banner
                    sock.sendall(b"\r\n")
                
                sock.settimeout(2.0)
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                result["banner"] = banner[:256]  # Cap at 256 chars
                
                # Parse banner for product/version
                parsed = _parse_banner(banner, port)
                result["product"] = parsed.get("product", "unknown")
                result["version"] = parsed.get("version", "unknown")
                
            except (socket.timeout, ConnectionResetError, OSError):
                result["product"] = get_service_name(port)
                result["version"] = "detected"
        
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError):
        result["state"] = "closed"
    
    return result


def real_port_scan(ip: str, ports: List[int], timeout: float = 2.0, max_workers: int = 20) -> List[Dict[str, Any]]:
    """Scan multiple ports concurrently using TCP connect scan."""
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_single_port, ip, port, timeout): port 
            for port in ports
        }
        
        for future in concurrent.futures.as_completed(future_to_port):
            try:
                result = future.result(timeout=timeout + 2)
                results.append(result)
            except Exception:
                port = future_to_port[future]
                results.append({
                    "port": port,
                    "service": get_service_name(port),
                    "state": "filtered",
                    "product": "unknown",
                    "version": "unknown",
                    "banner": ""
                })
    
    # Sort by port number
    results.sort(key=lambda x: x["port"])
    return results


def _parse_banner(banner: str, port: int) -> Dict[str, str]:
    """Extract product and version from a service banner."""
    info = {"product": "unknown", "version": "unknown"}
    
    if not banner:
        return info
    
    banner_lower = banner.lower()
    
    # SSH
    if banner_lower.startswith("ssh-"):
        info["product"] = "OpenSSH" if "openssh" in banner_lower else "SSH Server"
        parts = banner.split("-")
        if len(parts) >= 3:
            info["version"] = parts[2].split(" ")[0] if len(parts[2]) > 0 else "unknown"
    
    # HTTP Server headers
    elif "server:" in banner_lower:
        for line in banner.split("\r\n"):
            if line.lower().startswith("server:"):
                server_val = line.split(":", 1)[1].strip()
                if "nginx" in server_val.lower():
                    info["product"] = "nginx"
                    parts = server_val.split("/")
                    info["version"] = parts[1] if len(parts) > 1 else "unknown"
                elif "apache" in server_val.lower():
                    info["product"] = "Apache HTTPD"
                    parts = server_val.split("/")
                    info["version"] = parts[1].split(" ")[0] if len(parts) > 1 else "unknown"
                elif "microsoft-iis" in server_val.lower() or "iis" in server_val.lower():
                    info["product"] = "Microsoft IIS"
                    parts = server_val.split("/")
                    info["version"] = parts[1] if len(parts) > 1 else "unknown"
                else:
                    info["product"] = server_val.split("/")[0]
                    parts = server_val.split("/")
                    info["version"] = parts[1] if len(parts) > 1 else "unknown"
    
    # FTP
    elif port == 21 and ("ftp" in banner_lower or "220" in banner):
        info["product"] = "FTP Server"
        if "vsftpd" in banner_lower:
            info["product"] = "vsftpd"
        elif "proftpd" in banner_lower:
            info["product"] = "ProFTPD"
        elif "filezilla" in banner_lower:
            info["product"] = "FileZilla FTP"
        # Try to extract version
        import re
        ver_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
        if ver_match:
            info["version"] = ver_match.group(1)
    
    # SMTP
    elif port == 25 and ("smtp" in banner_lower or "220" in banner):
        info["product"] = "SMTP Server"
        if "postfix" in banner_lower:
            info["product"] = "Postfix"
        elif "exim" in banner_lower:
            info["product"] = "Exim"
    
    # Redis
    elif "redis" in banner_lower or port == 6379:
        info["product"] = "Redis"
        import re
        ver_match = re.search(r'redis_version:(\S+)', banner)
        if ver_match:
            info["version"] = ver_match.group(1)
    
    # MySQL
    elif port == 3306:
        info["product"] = "MySQL/MariaDB"
        import re
        ver_match = re.search(r'(\d+\.\d+\.\d+)', banner)
        if ver_match:
            info["version"] = ver_match.group(1)
    
    # Generic version detection
    else:
        import re
        ver_match = re.search(r'(\d+\.\d+[\.\d]*)', banner)
        if ver_match:
            info["version"] = ver_match.group(1)
        info["product"] = get_service_name(port)
    
    return info


# ─────────────────── DNS Lookup ───────────────────

def real_dns_lookup(domain: str) -> Dict[str, Any]:
    """Perform real DNS record lookups for a domain."""
    records = {
        "A": "N/A",
        "AAAA": "N/A",
        "MX": "N/A",
        "NS": [],
        "TXT": "N/A",
        "SPF": "No SPF record found",
        "DMARC": "No DMARC record found"
    }
    
    if not HAS_DNS:
        # Fallback to socket
        try:
            ip = socket.gethostbyname(domain)
            records["A"] = ip
        except socket.gaierror:
            pass
        return records
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10
    
    # A record
    try:
        answers = resolver.resolve(domain, "A")
        records["A"] = ", ".join([r.to_text() for r in answers])
    except Exception:
        pass
    
    # AAAA record
    try:
        answers = resolver.resolve(domain, "AAAA")
        records["AAAA"] = ", ".join([r.to_text() for r in answers])
    except Exception:
        pass
    
    # MX record
    try:
        answers = resolver.resolve(domain, "MX")
        mx_list = []
        for r in answers:
            mx_list.append(f"{r.exchange.to_text()} (Priority: {r.preference})")
        records["MX"] = ", ".join(mx_list) if mx_list else "N/A"
    except Exception:
        pass
    
    # NS record
    try:
        answers = resolver.resolve(domain, "NS")
        records["NS"] = [r.to_text() for r in answers]
    except Exception:
        pass
    
    # TXT records (includes SPF)
    try:
        answers = resolver.resolve(domain, "TXT")
        txt_entries = []
        for r in answers:
            txt_val = r.to_text().strip('"')
            txt_entries.append(txt_val)
            if txt_val.startswith("v=spf1"):
                records["SPF"] = _analyze_spf(txt_val)
        records["TXT"] = "; ".join(txt_entries) if txt_entries else "N/A"
    except Exception:
        pass
    
    # DMARC
    try:
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in answers:
            txt_val = r.to_text().strip('"')
            if "v=DMARC1" in txt_val.upper() or "v=dmarc1" in txt_val.lower():
                records["DMARC"] = _analyze_dmarc(txt_val)
                break
    except Exception:
        pass
    
    return records


def _analyze_spf(spf_record: str) -> str:
    """Analyze an SPF record for security posture."""
    if "-all" in spf_record:
        return f"HardFail (-all) — Strong protection. Record: {spf_record}"
    elif "~all" in spf_record:
        return f"SoftFail (~all) — Moderate protection, spoofing partially possible. Record: {spf_record}"
    elif "?all" in spf_record:
        return f"Neutral (?all) — Weak protection. Record: {spf_record}"
    elif "+all" in spf_record:
        return f"DANGEROUS (+all) — Allows all senders, spoofing trivially possible. Record: {spf_record}"
    return f"SPF found but no 'all' qualifier detected. Record: {spf_record}"


def _analyze_dmarc(dmarc_record: str) -> str:
    """Analyze a DMARC record for policy enforcement."""
    record_lower = dmarc_record.lower()
    if "p=reject" in record_lower:
        return f"Policy: REJECT — Strong enforcement. Record: {dmarc_record}"
    elif "p=quarantine" in record_lower:
        return f"Policy: QUARANTINE — Moderate enforcement. Record: {dmarc_record}"
    elif "p=none" in record_lower:
        return f"Policy: NONE — Monitoring only, no enforcement. Record: {dmarc_record}"
    return f"DMARC record found: {dmarc_record}"


# ─────────────────── GeoIP Lookup ───────────────────

def real_geoip_lookup(ip: str) -> Dict[str, Any]:
    """Perform real GeoIP lookup using ip-api.com (free, no key)."""
    geo_info = {
        "ip": ip,
        "isp": "Unknown",
        "org": "Unknown",
        "as": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "country": "Unknown",
        "geo_string": "Unknown",
        "lat": 0.0,
        "lon": 0.0
    }
    
    if not HAS_REQUESTS:
        return geo_info
    
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as",
            timeout=5
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                geo_info["isp"] = data.get("isp", "Unknown")
                geo_info["org"] = data.get("org", "Unknown")
                geo_info["as"] = data.get("as", "Unknown")
                geo_info["city"] = data.get("city", "Unknown")
                geo_info["region"] = data.get("regionName", "Unknown")
                geo_info["country"] = data.get("country", "Unknown")
                geo_info["lat"] = data.get("lat", 0.0)
                geo_info["lon"] = data.get("lon", 0.0)
                geo_info["geo_string"] = f"{data.get('city', '')}, {data.get('regionName', '')} ({data.get('country', '')})"
    except Exception:
        pass
    
    return geo_info


# ─────────────────── SSL/TLS Certificate Check ───────────────────

def real_ssl_check(host: str, port: int = 443, timeout: float = 5.0) -> Dict[str, Any]:
    """Perform a real SSL/TLS handshake and extract certificate details."""
    ssl_info = {
        "has_ssl": False,
        "tls_version": "N/A",
        "cipher": "N/A",
        "issuer": "N/A",
        "subject": "N/A",
        "san": [],
        "not_before": "N/A",
        "not_after": "N/A",
        "days_until_expiry": -1,
        "is_expired": False,
        "serial_number": "N/A",
        "certificate_grade": "F"
    }
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Accept self-signed too
        
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                ssl_info["has_ssl"] = True
                ssl_info["tls_version"] = ssock.version() or "Unknown"
                
                cipher_info = ssock.cipher()
                if cipher_info:
                    ssl_info["cipher"] = f"{cipher_info[0]} ({cipher_info[2]}-bit)"
                
                cert = ssock.getpeercert(binary_form=True)
                
                # Try to get parsed cert
                try:
                    # Re-connect with verification for parsed cert
                    ctx2 = ssl.create_default_context()
                    ctx2.check_hostname = False
                    ctx2.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=timeout) as s2:
                        with ctx2.wrap_socket(s2, server_hostname=host) as ss2:
                            parsed_cert = ss2.getpeercert()
                            if parsed_cert:
                                # Issuer
                                issuer_parts = []
                                for rdn in parsed_cert.get("issuer", []):
                                    for attr_name, attr_val in rdn:
                                        if attr_name in ("organizationName", "commonName"):
                                            issuer_parts.append(attr_val)
                                ssl_info["issuer"] = " / ".join(issuer_parts) if issuer_parts else "Unknown"
                                
                                # Subject
                                subject_parts = []
                                for rdn in parsed_cert.get("subject", []):
                                    for attr_name, attr_val in rdn:
                                        if attr_name == "commonName":
                                            subject_parts.append(attr_val)
                                ssl_info["subject"] = ", ".join(subject_parts) if subject_parts else "Unknown"
                                
                                # SAN
                                san_list = parsed_cert.get("subjectAltName", [])
                                ssl_info["san"] = [v for _, v in san_list]
                                
                                # Dates
                                not_before = parsed_cert.get("notBefore", "")
                                not_after = parsed_cert.get("notAfter", "")
                                ssl_info["not_before"] = not_before
                                ssl_info["not_after"] = not_after
                                
                                if not_after:
                                    try:
                                        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                        days_left = (expiry_dt - datetime.utcnow()).days
                                        ssl_info["days_until_expiry"] = days_left
                                        ssl_info["is_expired"] = days_left < 0
                                    except ValueError:
                                        pass
                                
                                ssl_info["serial_number"] = parsed_cert.get("serialNumber", "N/A")
                except Exception:
                    pass
                
                # Grade
                tls_ver = ssl_info["tls_version"]
                days = ssl_info["days_until_expiry"]
                if ssl_info["is_expired"]:
                    ssl_info["certificate_grade"] = "F"
                elif "TLSv1.3" in tls_ver:
                    ssl_info["certificate_grade"] = "A+" if days > 30 else "A"
                elif "TLSv1.2" in tls_ver:
                    ssl_info["certificate_grade"] = "A" if days > 30 else "B"
                elif "TLSv1.1" in tls_ver:
                    ssl_info["certificate_grade"] = "C"
                elif "TLSv1" in tls_ver:
                    ssl_info["certificate_grade"] = "D"
                else:
                    ssl_info["certificate_grade"] = "B"
    
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError):
        pass
    
    return ssl_info


# ─────────────────── HTTP Security Headers ───────────────────

def real_http_headers(host: str, use_https: bool = True) -> Dict[str, Any]:
    """Check real HTTP security headers on a target."""
    headers_result = {}
    
    SECURITY_HEADERS = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Referrer-Policy",
        "Permissions-Policy",
        "Cross-Origin-Opener-Policy"
    ]
    
    if not HAS_REQUESTS:
        for h in SECURITY_HEADERS:
            headers_result[h] = {"status": "Unknown", "value": "requests library not available"}
        return headers_result
    
    protocol = "https" if use_https else "http"
    url = f"{protocol}://{host}"
    
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True, verify=False)
        resp_headers = resp.headers
        
        for header_name in SECURITY_HEADERS:
            val = resp_headers.get(header_name)
            if val:
                headers_result[header_name] = {"status": "Present", "value": val}
            else:
                headers_result[header_name] = {"status": "Missing", "value": f"Header '{header_name}' not set — recommended to add"}
        
        # Also capture server header
        server = resp_headers.get("Server", "Not disclosed")
        headers_result["_server"] = server
        headers_result["_status_code"] = resp.status_code
        
    except requests.exceptions.SSLError:
        # Try HTTP fallback
        if use_https:
            return real_http_headers(host, use_https=False)
        for h in SECURITY_HEADERS:
            headers_result[h] = {"status": "Error", "value": "Connection failed"}
    except Exception as e:
        for h in SECURITY_HEADERS:
            headers_result[h] = {"status": "Error", "value": f"Connection failed: {str(e)[:80]}"}
    
    return headers_result


# ─────────────────── Subdomain Enumeration ───────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "admin", "cdn", "vpn",
    "ftp", "webmail", "portal", "test", "app", "blog", "shop",
    "ns1", "ns2", "mx", "smtp", "pop", "imap"
]

def real_subdomain_scan(domain: str, subdomains: List[str] = None) -> List[Dict[str, Any]]:
    """Probe common subdomains via DNS resolution."""
    if subdomains is None:
        subdomains = COMMON_SUBDOMAINS
    
    results = []
    
    def check_subdomain(sub: str) -> Optional[Dict]:
        fqdn = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            risk = "Low"
            if sub in ("admin", "phpmyadmin", "cpanel"):
                risk = "Critical"
            elif sub in ("dev", "staging", "test"):
                risk = "High"
            elif sub in ("api", "vpn", "ftp"):
                risk = "Medium"
            return {"subdomain": fqdn, "status": "Active", "ip": ip, "risk": risk}
        except socket.gaierror:
            return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result(timeout=5)
                if result:
                    results.append(result)
            except Exception:
                pass
    
    results.sort(key=lambda x: x["subdomain"])
    return results


# ─────────────────── Full Recon Orchestrator ───────────────────

def full_recon_scan(
    ip: str,
    domain: str = None,
    ports: List[int] = None,
    timeout: float = 2.0
) -> Dict[str, Any]:
    """
    Orchestrate a complete real reconnaissance scan.
    Returns a unified result dict compatible with the CyberGuardAgentPipeline.
    """
    if ports is None:
        ports = [21, 22, 23, 25, 80, 110, 143, 389, 443, 445, 
                 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]
    
    print(f"[Scanner] Starting real scan on {ip} ({domain or 'no domain'})...")
    scan_start = time.time()
    
    # 1. Port Scan
    print(f"[Scanner] Scanning {len(ports)} ports...")
    port_results = real_port_scan(ip, ports, timeout=timeout)
    open_ports = [p for p in port_results if p["state"] == "open"]
    print(f"[Scanner] Found {len(open_ports)} open ports out of {len(ports)} scanned.")
    
    # 2. DNS Lookup (if domain provided)
    dns_records = {}
    if domain and domain != ip:
        print(f"[Scanner] Performing DNS lookup for {domain}...")
        dns_records = real_dns_lookup(domain)
    else:
        dns_records = {
            "A": ip, "MX": "N/A", "TXT": "N/A", "NS": [],
            "SPF": "No domain provided for SPF check",
            "DMARC": "No domain provided for DMARC check"
        }
    
    # 3. GeoIP
    print(f"[Scanner] Looking up GeoIP for {ip}...")
    geo = real_geoip_lookup(ip)
    
    # 4. SSL Check (if 443 is open)
    ssl_data = {}
    has_443 = any(p["port"] == 443 and p["state"] == "open" for p in port_results)
    has_8443 = any(p["port"] == 8443 and p["state"] == "open" for p in port_results)
    
    ssl_target = domain if domain and domain != ip else ip
    if has_443:
        print(f"[Scanner] Checking SSL/TLS on port 443...")
        ssl_data = real_ssl_check(ssl_target, 443)
    elif has_8443:
        print(f"[Scanner] Checking SSL/TLS on port 8443...")
        ssl_data = real_ssl_check(ssl_target, 8443)
    
    # 5. HTTP Security Headers
    headers_data = {}
    has_http = any(p["port"] in (80, 443, 8080, 8443) and p["state"] == "open" for p in port_results)
    if has_http:
        print(f"[Scanner] Checking HTTP security headers...")
        headers_data = real_http_headers(ssl_target, use_https=has_443)
    
    # 6. Subdomain Enumeration
    subdomains = []
    if domain and domain != ip and "." in domain:
        # Extract base domain
        parts = domain.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        print(f"[Scanner] Enumerating subdomains for {base_domain}...")
        subdomains = real_subdomain_scan(base_domain)
    
    scan_duration = round(time.time() - scan_start, 2)
    print(f"[Scanner] Scan completed in {scan_duration}s.")
    
    # Build unified recon result
    recon_data = {
        "target": domain or ip,
        "ip": ip,
        "isp": f"{geo['isp']} - {geo['as']}",
        "geo": geo["geo_string"],
        "ports": open_ports,  # Only open ports
        "all_ports_scanned": port_results,  # Full scan results
        "dns_records": dns_records,
        "threat_intel": {
            "malware_score": "Unknown (real scan)",
            "known_botnet": False,
            "spam_blocklist": "Not checked"
        },
        "geo_details": geo,
        "ssl_info": ssl_data,
        "security_headers": headers_data,
        "subdomains": subdomains,
        "scan_metadata": {
            "scan_type": "REAL",
            "scan_duration_seconds": scan_duration,
            "scan_timestamp": datetime.utcnow().isoformat() + "Z",
            "ports_scanned": len(ports),
            "ports_open": len(open_ports)
        }
    }
    
    return recon_data
