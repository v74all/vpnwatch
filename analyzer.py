
import asyncio
import socket
import os
import ssl
import re
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime

import aiohttp
import dns.resolver
import OpenSSL.crypto
import certifi
import yaml
from loguru import logger
from pydantic import BaseModel, Field
from aiocache import cached, Cache

from core import handle_error, sync_supported
from constants import (
    V2RAY_SECURE_PORTS, V2RAY_COMMON_PORTS,
    AVAILABLE_APIS, DANGEROUS_PORTS, HIGH_RISK_PORTS
)

CACHE_TTL = 600

class APIKeys(BaseModel):
    VirusTotal: Optional[str] = Field(None, env="VIRUSTOTAL_API_KEY")
    AbuseIPDB: Optional[str] = Field(None, env="ABUSEIPDB_API_KEY")
    Shodan: Optional[str] = Field(None, env="SHODAN_API_KEY")
    SecurityTrails: Optional[str] = Field(None, env="SECURITYTRAILS_API_KEY")
    IPQualityScore: Optional[str] = Field(None, env="IPQUALITYSCORE_API_KEY")

class ScanSettings(BaseModel):
    default_timeout: float = 5.0
    max_concurrent_scans: int = 500

class Config(BaseModel):
    api_keys: APIKeys
    scan_settings: ScanSettings

    @classmethod
    def from_yaml(cls, filepath: str):
        with open(filepath, 'r') as file:
            data = yaml.safe_load(file)
        return cls(**data)

config = Config.from_yaml('config.yaml')


async def test_mtu(ip: str, mtu: int) -> bool:
    return True

async def measure_latency(ip: str) -> Optional[float]:
    return 10.0

def calculate_jitter(latency_samples: List[float]) -> float:
    return max(latency_samples) - min(latency_samples)


@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def traceroute(ip: str, max_hops: int = 15) -> List[Dict[str, Any]]:
    results = []
    timeout_per_hop = 0.5

    if ip == "127.0.0.1" or ip == "localhost":
        results.append({
            "hop": 1,
            "ip": "127.0.0.1",
            "latency": 0.1,
            "hostname": "localhost"
        })
        return results

    for ttl in range(1, max_hops + 1):
        try:
            cmd = ['tracert', '-h', str(ttl), '-w', '500', ip] if os.name == 'nt' else ['traceroute', '-n', '-w', '1', '-q', '1', '-m', str(ttl), ip]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                lines = stdout.decode().splitlines()
                for line in lines:
                    if os.name == 'nt':
                        if ttl > 1 and ' ms' in line:
                            parts = line.strip().split()
                            ip_addr = parts[-1].strip('[]')
                            latency = float(parts[-2])
                            results.append({
                                "hop": ttl,
                                "ip": ip_addr,
                                "latency": latency,
                                "hostname": ip_addr
                            })
                    else:
                        if ' ms' in line:
                            parts = line.strip().split()
                            ip_addr = parts[1]
                            try:
                                latency = float(parts[2])
                            except (IndexError, ValueError):
                                latency = None
                            results.append({
                                "hop": ttl,
                                "ip": ip_addr,
                                "latency": latency,
                                "hostname": ip_addr
                            })

            if any(r.get('ip') == ip for r in results):
                break

        except Exception as e:
            logger.debug(f"Traceroute error at hop {ttl}: {str(e)}")
            results.append({
                "hop": ttl,
                "ip": "*",
                "latency": None,
                "hostname": None
            })

        await asyncio.sleep(0.05)

    return results

@handle_error
@cached(ttl=300, cache=Cache.MEMORY)
async def scan_common_ports(ip: str, ports: List[int], batch_size: int = 100, timeout: float = 0.5) -> Dict[int, Dict[str, Any]]:
    results = {}
    semaphore = asyncio.Semaphore(config.scan_settings.max_concurrent_scans)

    common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 5432, 8080]
    ports = list(set(ports + common_ports))

    async def check_single_port(port: int) -> Tuple[int, bool, Optional[str]]:
        async with semaphore:
            try:
                if ip in ["127.0.0.1", "localhost"]:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex(('127.0.0.1', port))
                    sock.close()
                    if result == 0:
                        try:
                            service = socket.getservbyport(port, 'tcp')
                        except:
                            service = 'unknown'
                        return port, True, service
                    return port, False, None
                else:
                    future = asyncio.open_connection(ip, port)
                    reader, writer = await asyncio.wait_for(future, timeout=timeout)
                    writer.close()
                    await writer.wait_closed()
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        service = 'unknown'
                    return port, True, service
            except (asyncio.TimeoutError, ConnectionRefusedError, socket.error):
                return port, False, None
            except Exception as e:
                logger.debug(f"Port {port} scan error: {str(e)}")
                return port, False, None

    for i in range(0, len(ports), batch_size):
        batch = ports[i:i + batch_size]
        tasks = [check_single_port(p) for p in batch]

        try:
            batch_results = await asyncio.gather(*tasks)
            for port, is_open, service in batch_results:
                if is_open:
                    results[port] = {
                        'open': True,
                        'service': service
                    }
        except Exception as e:
            logger.error(f"Batch scan error: {str(e)}")

    return results

@handle_error
@sync_supported
@cached(ttl=600, cache=Cache.MEMORY)
async def deep_port_scan(ip: str, ports: List[int]) -> List[int]:
    try:
        results = await scan_common_ports(
            ip,
            ports,
            batch_size=len(ports),
            timeout=1.0
        )
        return sorted(port for port, info in results.items() if info.get('open', False))
    except Exception as e:
        logger.error(f"Port scan error: {e}")
        return []

@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def analyze_dns(domain: str) -> Dict[str, Any]:
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for record_type in record_types:
        try:
            answers = resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            results[record_type] = f"Error: {str(e)}"

    return results

@handle_error
@sync_supported
@cached(ttl=600, cache=Cache.MEMORY)
async def analyze_ssl_cert(ip: str, port: int = 443) -> Dict[str, Any]:
    result = {
        "subject": None, "issuer": None, "version": None, "serial_number": None,
        "not_before": None, "not_after": None, "expired": None,
        "signature_algorithm": None, "is_self_signed": None, "error": None
    }
    ctx = ssl.create_default_context(cafile=certifi.where())
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers('DEFAULT:@SECLEVEL=1')

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip),
            timeout=config.scan_settings.default_timeout
        )
        ssl_object = writer.get_extra_info('ssl_object')
        cert = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        if cert:
            try:
                x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                subj = dict(x509.get_subject().get_components())
                issr = dict(x509.get_issuer().get_components())
                result.update({
                    "subject": {k.decode(): v.decode() for k, v in subj.items()},
                    "issuer": {k.decode(): v.decode() for k, v in issr.items()},
                    "version": x509.get_version(),
                    "serial_number": str(x509.get_serial_number()),
                    "not_before": x509.get_notBefore().decode(),
                    "not_after": x509.getNotAfter().decode(),
                    "expired": x509.has_expired(),
                    "signature_algorithm": x509.get_signature_algorithm().decode(),
                    "is_self_signed": (subj == issr)
                })
            except Exception as e:
                result["error"] = f"Certificate parsing error: {e}"
        writer.close()
        await writer.wait_closed()
    except asyncio.TimeoutError:
        result["error"] = "Connection timeout"
    except Exception as e:
        result["error"] = f"SSL connection error: {e}"
    return result

@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def analyze_protocols(ip: str) -> Dict[str, Any]:
    results = {
        'supported_protocols': [],
        'security_issues': []
    }

    protocols = {
        1194: 'OpenVPN',
        1701: 'L2TP',
        1723: 'PPTP',
        500: 'IPSec',
        4500: 'IPSec NAT-T',
        8388: 'Shadowsocks',
        8443: 'V2Ray/Trojan',
        51820: 'WireGuard'
    }

    open_ports_dict = await scan_common_ports(ip, list(protocols.keys()))

    for port, info in open_ports_dict.items():
        if info.get('open'):
            protocol = protocols.get(port, 'Unknown')
            results['supported_protocols'].append({
                'port': port,
                'protocol': protocol
            })

            if port == 1723:
                results['security_issues'].append({
                    'protocol': 'PPTP',
                    'severity': 'High',
                    'description': 'PPTP is considered cryptographically broken'
                })
            elif port in [500, 4500]:
                results['security_issues'].append({
                    'protocol': 'IPSec',
                    'severity': 'Info',
                    'description': 'Verify using strong encryption algorithms'
                })

    return results

@handle_error
@sync_supported
@cached(ttl=600, cache=Cache.MEMORY)
async def enhanced_ssl_analysis(ip: str, port: int = 443) -> Dict[str, Any]:
    result = {
        "ssl_enabled": False,
        "protocols": [],
        "cipher_suites": [],
        "certificate": None,
        "vulnerabilities": [],
        "error": None
    }

    protocols = [
        ssl.PROTOCOL_TLSv1_2,
        ssl.PROTOCOL_TLSv1_1,
        ssl.PROTOCOL_TLSv1,
        ssl.PROTOCOL_SSLv23,
    ]

    for protocol in protocols:
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers('ALL:@SECLEVEL=0')

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=ip),
                timeout=5.0
            )

            ssl_obj = writer.get_extra_info('ssl_object')
            if ssl_obj:
                result["ssl_enabled"] = True
                
                version = ssl_obj.version()
                if version:
                    result["protocols"].append(version)

                cipher = ssl_obj.cipher()
                if cipher:
                    result["cipher_suites"].append({
                        'name': cipher[0],
                        'version': cipher[1],
                        'bits': cipher[2]
                    })

                cert = ssl_obj.getpeercert(binary_form=True)
                if cert:
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
                    result["certificate"] = {
                        "subject": dict((k.decode(), v.decode()) 
                            for k, v in dict(x509.get_subject().get_components()).items()),
                        "issuer": dict((k.decode(), v.decode()) 
                            for k, v in dict(x509.get_issuer().get_components()).items()),
                        "version": x509.get_version(),
                        "not_before": x509.get_notBefore().decode(),
                        "not_after": x509.getNotAfter().decode(),
                        "expired": x509.has_expired(),
                        "serial_number": str(x509.get_serial_number())
                    }

                if 'SSLv3' in str(version):
                    result["vulnerabilities"].append({
                        'name': 'POODLE',
                        'severity': 'High',
                        'description': 'SSLv3 is vulnerable to POODLE attack'
                    })
                if 'TLSv1.0' in str(version):
                    result["vulnerabilities"].append({
                        'name': 'BEAST',
                        'severity': 'Medium',
                        'description': 'TLSv1.0 may be vulnerable to BEAST attack'
                    })

            writer.close()
            await writer.wait_closed()

        except ssl.SSLError as e:
            logger.debug(f"SSL protocol {protocol} not supported: {e}")
            continue
        except Exception as e:
            logger.error(f"SSL analysis error: {e}")
            continue

    if not result["ssl_enabled"]:
        result["error"] = "SSL/TLS not enabled on this port"
        
    return result

@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def check_blacklists(ip: str) -> List[str]:
    hits = []
    blocklist_urls = [
        "https://api.blocklist.de/api.php",
        "https://www.abuseipdb.com/check"
    ]
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
        for base_url in blocklist_urls:
            try:
                if "blocklist.de" in base_url:
                    url = f"{base_url}?ip={ip}&cmd=info"
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if any(ind in text.lower() for ind in ["listed","attacks","reports"]):
                                hits.append("blocklist.de")
                elif "abuseipdb" in base_url:
                    url = f"https://api.abuseipdb.com/api/v2/check"
                    headers = {"Accept": "application/json", "Key": config.api_keys.AbuseIPDB}
                    params = {"ipAddress": ip, "maxAgeInDays": 90}
                    async with session.get(url, headers=headers, params=params) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            score = data.get("data", {}).get("abuseConfidenceScore", 0)
                            if score > 25:
                                hits.append("abuseipdb")
            except:
                continue
    return hits

@handle_error
@sync_supported
def whois_lookup(address: str) -> Dict[str, Any]:
    results = {
        "error": None, "domain_name": None, "creation_date": None,
        "expiration_date": None, "registrar": None, "whois_server": None,
        "status": None, "type": None
    }
    try:
        import whois
        import ipwhois
        import re
        from datetime import datetime

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', address):
            try:
                ip_who = ipwhois.IPWhois(address)
                whois_data = ip_who.lookup_whois()
                results.update({
                    "ip_address": address, "type": "ip",
                    "asn": whois_data.get('asn'),
                    "asn_description": whois_data.get('asn_description'),
                    "network": whois_data.get('network'),
                    "organization": whois_data.get('nets', [{}])[0].get('description')
                })
                return results
            except Exception as e:
                logger.debug(f"IP-based whois error: {e}")

        try:
            w = whois.whois(address)
            if w:
                creation_date = w.creation_date.isoformat() if isinstance(w.creation_date, datetime) else str(w.creation_date)
                expiration_date = w.expiration_date.isoformat() if isinstance(w.expiration_date, datetime) else str(w.expiration_date)
                results.update({
                    "domain_name": w.domain_name,
                    "creation_date": creation_date,
                    "expiration_date": expiration_date,
                    "registrar": getattr(w, 'registrar', None),
                    "whois_server": getattr(w, 'whois_server', None),
                    "status": w.status,
                    "type": "domain"
                })
        except Exception as e:
            logger.debug(f"Domain whois error: {e}")
    except Exception as e:
        results["error"] = str(e)
    return results

@sync_supported
async def check_vulnerabilities(ip: str, ports: List[int]) -> Dict[int, Dict[str, Any]]:
    vulnerabilities = {}
    for port in ports:
        if port == 22:
            vulnerabilities[port] = {"notes": "SSH checks not fully implemented"}
        elif port in [80, 443]:
            vulnerabilities[port] = {"notes": "HTTP/HTTPS checks not fully implemented"}
            result = await advanced_http_analysis(ip, port)
            vulnerabilities[port] = {"notes": "HTTP/HTTPS checks", "analysis": result}
    return vulnerabilities

@handle_error
@sync_supported
@cached(ttl=600, cache=Cache.MEMORY)
async def analyze_with_apis(ip: str) -> Dict[str, Any]:
    return {}

@handle_error
@sync_supported
@cached(ttl=600, cache=Cache.MEMORY)
async def get_system_ip(timeout_sec: int = 10, **kwargs) -> Tuple[str, List[str]]:
    services = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
        "https://ipinfo.io/json",
        "https://api.myip.com",
        "https://ip.seeip.org/json"
    ]
    hits = []
    ip = None

    def get_local_ip():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(0.1)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except:
            return None

    async with aiohttp.ClientSession() as session:
        for service in services:
            try:
                async with session.get(service, timeout=timeout_sec) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            if isinstance(data, dict):
                                candidate = data.get("ip") or data.get("ipAddress") or data.get("query")
                                if candidate and isinstance(candidate, str):
                                    ip = candidate
                                    break
                        except:
                            text = await resp.text()
                            if text and len(text.strip().split()) == 1:
                                ip = text.strip()
                                break
            except:
                continue

        if not ip:
            ip = get_local_ip()

        if not ip:
            raise ValueError("Unable to determine system IP - check network connection")

        if ip and not ip.startswith(('192.168.', '10.', '172.16.', '127.')):
            blocklist_urls = [
                f"https://api.blocklist.de/api.php?ip={ip}",
                f"https://www.abuseipdb.com/check/{ip}"
            ]
            for url in blocklist_urls:
                try:
                    async with session.get(url, timeout=5) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if "listed" in text.lower():
                                hits.append(url)
                except:
                    continue

    return ip, hits

async def scan_open_ports(ip: str, port_range: Tuple[int, int]) -> List[int]:
    start_port, end_port = port_range
    ports = list(range(start_port, end_port + 1))
    return await deep_port_scan(ip, ports)

class ScanCache:
    _instance = None
    _cache = {}
    _lock = asyncio.Lock()
    
    @classmethod
    async def get(cls, key: str) -> Optional[Dict]:
        async with cls._lock:
            if key in cls._cache:
                entry = cls._cache[key]
                if (datetime.now() - entry['timestamp']).seconds < CACHE_TTL:
                    return entry['data']
            return None
            
    @classmethod
    async def set(cls, key: str, data: Dict):
        async with cls._lock:
            cls._cache[key] = {
                'data': data,
                'timestamp': datetime.now()
            }
            
    @classmethod
    async def clear_expired(cls):
        async with cls._lock:
            now = datetime.now()
            expired = [k for k, v in cls._cache.items() 
                      if (now - v['timestamp']).seconds >= CACHE_TTL]
            for k in expired:
                del cls._cache[k]

@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def analyze_v2ray_security(ip: str) -> Dict[str, Any]:
    v2ray_ports = [1080, 10808, 10809, 8443]
    analysis = {"open_ports": [], "warnings": []}
    open_ports = await scan_common_ports(ip, v2ray_ports)
    for port, info in open_ports.items():
        if info.get('open'):
            analysis["open_ports"].append(port)
            analysis["warnings"].append({
                "port": port,
                "message": "Verify V2Ray config to avoid potential hacks."
            })
    return analysis

@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def detect_os_by_ttl(ip: str) -> str:
    import subprocess, sys
    cmd = ["ping", "-c", "1", ip] if sys.platform != "win32" else ["ping", "-n", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode().lower()
        if "ttl=64" in output:
            return "Linux/Unix"
        elif "ttl=128" in output:
            return "Windows"
        elif "ttl=255" in output:
            return "Cisco/Networking device"
    except:
        pass
    return "Unknown"

@handle_error
@sync_supported
async def perform_full_scan(ip: str, progress_callback=None, scan_type: str = "direct_ip", **kwargs) -> Dict[str, Any]:
    cache_key = f"full_scan_{ip}_{scan_type}"
    total_steps = 9
    current_step = 0
    scan_status = {}
    
    def update_progress(message: str, status: bool = True):
        nonlocal current_step
        current_step += 1
        scan_status[message] = status
        if progress_callback:
            percentage = int((current_step / total_steps) * 100)
            progress_callback({
                "percentage": percentage,
                "message": message,
                "current_step": current_step,
                "total_steps": total_steps,
                "scan_status": scan_status,
                "scan_type": scan_type
            })
    
    results = {
        "ip": ip,
        "timestamp": datetime.now().isoformat(),
        "scan_type": scan_type,
        "valid": True,
        "scan_completion": {
            "total_steps": total_steps,
            "completed_steps": 0,
            "scan_status": {},
            "completed_scans": {}
        }
    }

    try:
        update_progress("Performing comprehensive port scan...")
        try:
            ports = await deep_port_scan(ip, list(range(1, 65536)))
            results["port_scan"] = {
                "total_ports_scanned": len(ports),
                "open_ports": ports,
                "dangerous_ports": [p for p in ports if p in DANGEROUS_PORTS],
                "high_risk_ports": [p for p in ports if p in HIGH_RISK_PORTS],
                "status": "completed"
            }
            results["scan_completion"]["completed_scans"]["port_scan"] = True
            results["scan_completion"]["scan_status"]["port_scan"] = True
        except Exception as e:
            results["valid"] = False
            results["port_scan"] = {"error": str(e), "status": "failed"}
            update_progress("Port scan failed", False)

        update_progress("Analyzing network protocols...")
        try:
            protocol_results = await analyze_protocols(ip)
            results["protocols"] = protocol_results
            results["scan_completion"]["scan_status"]["protocol_analysis"] = True
        except Exception as e:
            results["protocols"] = {"error": str(e)}
            update_progress("Protocol analysis failed", False)

        update_progress("Performing SSL/TLS security analysis...")
        try:
            ssl_ports = [443, 8443, 9443]
            ssl_results = {}
            
            for port in ssl_ports:
                if port in results.get("port_scan", {}).get("open_ports", []):
                    port_result = await enhanced_ssl_analysis(ip, port)
                    if port_result.get("ssl_enabled"):
                        ssl_results[port] = port_result

            if ssl_results:
                results["ssl_security"] = ssl_results
                results["scan_completion"]["scan_status"]["ssl_analysis"] = True
            else:
                results["ssl_security"] = {"error": "No SSL/TLS services found"}
                results["scan_completion"]["scan_status"]["ssl_analysis"] = False
        except Exception as e:
            results["ssl_security"] = {"error": str(e)}
            update_progress("SSL analysis failed", False)

        update_progress("Analyzing network path...")
        try:
            trace_results = await traceroute(ip)
            valid_latencies = [hop["latency"] for hop in trace_results if hop["latency"] is not None]
            
            results["network_path"] = {
                "traceroute": trace_results,
                "hops": len(trace_results),
                "latency_stats": {
                    "average": sum(valid_latencies) / len(valid_latencies) if valid_latencies else 0,
                    "total_hops": len(trace_results),
                    "responding_hops": len(valid_latencies)
                }
            }
            results["scan_completion"]["scan_status"]["network_analysis"] = True
        except Exception as e:
            results["network_path"] = {
                "error": str(e),
                "traceroute": [],
                "latency_stats": {
                    "average": 0,
                    "total_hops": 0,
                    "responding_hops": 0
                }
            }
            update_progress("Network path analysis failed", False)

        update_progress("Performing security checks...")
        try:
            blacklist_results = await check_blacklists(ip)
            results["security"] = {
                "blacklists": blacklist_results,
                "risk_level": "High" if blacklist_results else "Low",
                "recommendations": []
            }
            results["scan_completion"]["scan_status"]["security_checks"] = True
        except Exception as e:
            results["security"] = {"error": str(e)}
            update_progress("Security checks failed", False)

        update_progress("Analyzing VPN configuration...")
        try:
            vpn_results = await analyze_v2ray_security(ip)
            results["vpn_security"] = vpn_results
            results["scan_completion"]["scan_status"]["vpn_analysis"] = True
        except Exception as e:
            results["vpn_security"] = {"error": str(e)}
            update_progress("VPN analysis failed", False)

        update_progress("Detecting operating system...")
        try:
            os_results = await detect_os_by_ttl(ip)
            results["system_info"] = {
                "os_guess": os_results,
                "detection_confidence": "Medium"
            }
            results["scan_completion"]["scan_status"]["os_detection"] = True
        except Exception as e:
            results["system_info"] = {"error": str(e)}
            update_progress("OS detection failed", False)

        update_progress("Checking for vulnerabilities...")
        try:
            vuln_results = await check_vulnerabilities(ip, results.get("port_scan", {}).get("open_ports", []))
            results["vulnerabilities"] = vuln_results
            results["scan_completion"]["scan_status"]["vulnerability_scan"] = True
        except Exception as e:
            results["vulnerabilities"] = {"error": str(e)}
            update_progress("Vulnerability scan failed", False)

        update_progress("Generating final analysis...")
        try:
            results["analysis_summary"] = generate_security_recommendations(results)
            results["scan_completion"]["scan_status"]["final_analysis"] = True
        except Exception as e:
            results["analysis_summary"] = {"error": str(e)}
            update_progress("Final analysis failed", False)

        completed_scans = sum(1 for status in results["scan_completion"]["scan_status"].values() if status)
        results["scan_completion"]["completed_steps"] = completed_scans
        results["scan_completion"]["percentage"] = (completed_scans / total_steps) * 100

        critical_steps = ["port_scan", "security_checks", "network_analysis"]
        results["valid"] = all(
            results["scan_completion"]["scan_status"].get(step, False) 
            for step in critical_steps
        )

        if progress_callback:
            progress_callback({
                "percentage": 100,
                "message": "Scan completed",
                "current_step": total_steps,
                "total_steps": total_steps,
                "scan_status": results["scan_completion"]["scan_status"]
            })

        if all(results["scan_completion"]["scan_status"].values()):
            await ScanCache.set(cache_key, results)

        return results

    except Exception as e:
        logger.error(f"Critical scan error: {e}")
        results["error"] = str(e)
        results["valid"] = False
        results["scan_completion"]["error"] = True
        if progress_callback:
            progress_callback({
                "percentage": 0,
                "message": f"Critical error during scan: {str(e)}",
                "error": True
            })
        return results

def generate_security_recommendations(results: Dict[str, Any]) -> Dict[str, Any]:
    recommendations = []
    risk_factors = []
    
    if not results.get("valid", False):
        return {
            "risk_factors": [{"severity": "High", "description": "Scan incomplete or invalid"}],
            "recommendations": ["Perform a new scan to get accurate results"],
            "overall_risk": "Unknown"
        }
    
    blacklists = results.get("security", {}).get("blacklists", [])
    if blacklists:
        risk_factors.append({
            "severity": "High",
            "description": f"Found in {len(blacklists)} blacklists"
        })
        recommendations.append("Investigate and address blacklist presence")

    dangerous_ports = results.get("port_scan", {}).get("dangerous_ports", [])
    if dangerous_ports:
        risk_factors.append({
            "severity": "High",
            "description": f"Dangerous ports open: {', '.join(map(str, dangerous_ports))}"
        })
        recommendations.append("Close or secure dangerous open ports")

    ssl_results = results.get("ssl_security", {})
    if isinstance(ssl_results, dict) and any(
        port_data.get("vulnerabilities") 
        for port_data in ssl_results.values() 
        if isinstance(port_data, dict)
    ):
        risk_factors.append({
            "severity": "High",
            "description": "SSL/TLS vulnerabilities detected"
        })
        recommendations.append("Upgrade SSL/TLS configuration")

    vpn_warnings = results.get("vpn_security", {}).get("warnings", [])
    if vpn_warnings:
        risk_factors.append({
            "severity": "Medium",
            "description": "VPN configuration issues detected"
        })
        recommendations.append("Review and secure VPN configuration")

    if not recommendations:
        recommendations.append("Continue monitoring for security issues")

    return {
        "risk_factors": risk_factors,
        "recommendations": recommendations,
        "overall_risk": calculate_risk_level(risk_factors)
    }

def calculate_risk_level(risk_factors: List[Dict[str, str]]) -> str:
    if any(rf["severity"] == "High" for rf in risk_factors):
        return "High"
    elif any(rf["severity"] == "Medium" for rf in risk_factors):
        return "Medium"
    return "Low"

@handle_error
@sync_supported
@cached(ttl=300, cache=Cache.MEMORY)
async def http_security_analysis(headers: Dict[str, str]) -> Dict[str, Any]:
    findings = {}
    if "Strict-Transport-Security" not in headers:
        findings["hsts"] = "Missing HSTS header"
    if "X-Frame-Options" not in headers:
        findings["x_frame_options"] = "Missing X-Frame-Options header"
    if "X-Content-Type-Options" not in headers:
        findings["x_content_type"] = "Missing X-Content-Type-Options header"
    if "X-XSS-Protection" not in headers:
        findings["x_xss_protection"] = "Missing X-XSS-Protection header"
    return findings

async def advanced_http_analysis(ip: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    import aiohttp
    url = f"http://{ip}:{port}" if port == 80 else f"https://{ip}:{port}"
    data = {"error": None, "headers": {}, "status": None}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
                data["status"] = resp.status
                data["headers"] = dict(resp.headers)
    except Exception as e:
        data["error"] = str(e)

    if not data["error"]:
        data["security_checks"] = await http_security_analysis(data["headers"])

    return data

__all__ = [
    'perform_full_scan',
    'get_system_ip',
    'traceroute',
    'analyze_dns',
    'analyze_ssl_cert',
    'deep_port_scan',
    'analyze_protocols',
    'enhanced_ssl_analysis',
    'check_blacklists',
    'analyze_with_apis',
    'check_vulnerabilities',
    'whois_lookup'
]
