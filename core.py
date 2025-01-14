import asyncio
from functools import wraps
from typing import Any, Dict, Optional, Protocol
from aiocache import Cache
from aiocache.serializers import JsonSerializer
import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from datetime import datetime
import yaml
from loguru import logger
from pydantic import BaseModel, Field
from constants import (
    CACHE_TTL, MAX_RETRIES, RETRY_DELAY, DEFAULT_TIMEOUT, VERSION,
    AvailableAPI
)

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

logger.remove()
logger.add("core.log", rotation="10 MB", retention="10 days", level="DEBUG")

class TimeoutError(Exception):
    pass

class RetryableError(Exception):
    pass

def handle_error(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except asyncio.TimeoutError:
            logger.error(f"TimeoutError in {func.__name__}")
            raise TimeoutError("Operation timed out")
        except Exception as e:
            logger.error(f"[handle_error] in {func.__name__}: {e}", exc_info=True)
            raise
    return wrapper

def sync_supported(func):
    func.sync_supported = True
    return func

class ResultValidator:
    @staticmethod
    def is_valid_result(result) -> bool:
        if not isinstance(result, dict):
            return False
        required_fields = ['analysis_timestamp', 'analyzer_version']
        return all(field in result for field in required_fields)

    @staticmethod
    def clean_result(result: dict) -> dict:
        if not isinstance(result, dict):
            logger.error("Invalid result format - not a dictionary.")
            return {"error": "Invalid result format", "valid": False}

        cleaned = {k: v for k, v in result.items() if v is not None}

        if 'analysis_timestamp' not in cleaned:
            cleaned['analysis_timestamp'] = datetime.now().isoformat()
        if 'analyzer_version' not in cleaned:
            cleaned['analyzer_version'] = VERSION

        return cleaned

class EnhancedCache(Cache):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._error_count = 0
        self._last_error = None

    async def get_with_fallback(self, key: str, fallback_func, *args, **kwargs):
        try:
            value = await self.get(key)
            if value is not None:
                return value

            value = await fallback_func(*args, **kwargs)
            await self.set(key, value)
            return value

        except Exception as e:
            self._error_count += 1
            self._last_error = e
            logger.error(f"Cache error: {e}")
            return await fallback_func(*args, **kwargs)

class CacheManager:
    cache = EnhancedCache(Cache.MEMORY, serializer=JsonSerializer(), ttl=CACHE_TTL)

    @classmethod
    async def get_or_execute(cls, key: str, func, *args, **kwargs):
        cached_result = await cls.cache.get(key)
        if cached_result:
            logger.debug(f"[Cache Hit] Key: {key}")
            return cached_result

        for attempt in range(MAX_RETRIES):
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)

                if ResultValidator.is_valid_result(result):
                    cleaned_result = ResultValidator.clean_result(result)
                    await cls.cache.set(key, cleaned_result, ttl=CACHE_TTL)
                    logger.debug(f"[Cache Set] Key: {key}")
                    return cleaned_result
                else:
                    raise RetryableError("Invalid result format")
            except RetryableError as e:
                logger.warning(f"Retryable error in {func.__name__}: {e}")
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_DELAY * (attempt + 1))
            except Exception as e:
                logger.error(f"Error executing {func.__name__}: {e}")
                return {"error": str(e), "valid": False}

        logger.error(f"[Cache] Max retries exceeded for key: {key}")
        return {"error": "Max retries exceeded", "valid": False}

class AsyncRetry:
    def __init__(self, retries=3, backoff_factor=1.5):
        self.retries = retries
        self.backoff_factor = backoff_factor

    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(self.retries):
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    last_exception = e
                    delay = (self.backoff_factor ** attempt) * RETRY_DELAY
                    logger.warning(f"Retry {attempt + 1}/{self.retries} for {func.__name__} in {delay:.1f}s")
                    await asyncio.sleep(delay)
            logger.error(f"[AsyncRetry] Max retries exceeded for {func.__name__}")
            raise last_exception
        return wrapper

class APIProtocol(Protocol):
    async def get_ip_info(self, ip: str) -> Dict[str, Any]: ...
    async def close(self) -> None: ...

class APIInterface(APIProtocol):
    pass

class APIClient(APIInterface):
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = ClientTimeout(total=timeout)
        self.connector = TCPConnector(limit=50)
        self.session: Optional[aiohttp.ClientSession] = None

    @classmethod
    async def create(cls, timeout: int = DEFAULT_TIMEOUT):
        client = cls(timeout)
        client.session = aiohttp.ClientSession(
            timeout=client.timeout,
            connector=client.connector
        )
        return client

    async def close(self):
        if self.session:
            await self.session.close()

    async def get_ip_info(self, ip: str) -> Dict[str, Any]:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=self.connector
            )
        try:
            url = f"https://ipinfo.io/{ip}/json"
            async with self.session.get(url) as resp:
                resp.raise_for_status()
                return await resp.json()
        except Exception as e:
            logger.error(f"API request failed: {e}")
            return {"error": str(e)}

class EnhancedAPIClient(APIClient):
    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        super().__init__(timeout)
        self._rate_limiter = asyncio.Semaphore(10)
        self._last_request: Dict[str, datetime] = {}

    @AsyncRetry(retries=3)
    async def rate_limited_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        async with self._rate_limiter:
            domain = url.split('/')[2]
            if domain in self._last_request:
                elapsed = datetime.now() - self._last_request[domain]
                if elapsed.total_seconds() < 1.0:
                    await asyncio.sleep(1.0 - elapsed.total_seconds())

            async with self.session.request(method, url, **kwargs) as response:
                self._last_request[domain] = datetime.now()
                response.raise_for_status()
                return await response.json()

class RateLimitedAPIClient(EnhancedAPIClient):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rate_limits: Dict[str, asyncio.Semaphore] = {}

    async def rate_limited_request(self, method: str, url: str, domain: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        domain = domain or url.split('/')[2]
        if domain not in self._rate_limits:
            self._rate_limits[domain] = asyncio.Semaphore(10)

        async with self._rate_limits[domain]:
            return await super().rate_limited_request(method, url, **kwargs)

@handle_error
@sync_supported
async def analyze_with_apis(ip: str, api_keys: Dict[str, str]) -> Dict[str, Any]:
    results = {}
    
    async def check_virustotal():
        if api_keys.get("VirusTotal"):
            async with aiohttp.ClientSession() as session:
                headers = {"x-apikey": api_keys["VirusTotal"]}
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        attributes = data.get("data", {}).get("attributes", {})
                        return {
                            "detected_urls": len(attributes.get("detected_urls", [])),
                            "detected_samples": len(attributes.get("last_analysis_stats", {}).get("malicious", [])),
                            "country": attributes.get("country", ""),
                            "as_owner": attributes.get("as_owner", ""),
                            "reputation": attributes.get("reputation", 0)
                        }
        return None

    async def check_abuseipdb():
        if api_keys.get("AbuseIPDB"):
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Accept": "application/json",
                    "Key": api_keys["AbuseIPDB"]
                }
                url = f"https://api.abuseipdb.com/api/v2/check"
                params = {"ipAddress": ip, "maxAgeInDays": 90}
                async with session.get(url, headers=headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        report = data.get("data", {})
                        return {
                            "abuse_score": report.get("abuseConfidenceScore", 0),
                            "total_reports": report.get("totalReports", 0),
                            "country_code": report.get("countryCode", ""),
                            "isp": report.get("isp", ""),
                            "domain": report.get("domain", ""),
                            "last_reported": report.get("lastReportedAt")
                        }
        return None

    async def check_shodan():
        if api_keys.get("Shodan"):
            async with aiohttp.ClientSession() as session:
                url = f"https://api.shodan.io/shodan/host/{ip}"
                params = {"key": api_keys["Shodan"]}
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "ports": data.get("ports", []),
                            "vulns": data.get("vulns", []),
                            "tags": data.get("tags", []),
                            "hostnames": data.get("hostnames", []),
                            "os": data.get("os", ""),
                            "organization": data.get("org", ""),
                            "isp": data.get("isp", ""),
                            "last_update": data.get("last_update", "")
                        }
        return None

    async def check_securitytrails():
        if api_keys.get("SecurityTrails"):
            async with aiohttp.ClientSession() as session:
                headers = {"Authorization": f"Bearer {api_keys['SecurityTrails']}"}
                url = f"https://api.securitytrails.com/v1/ip/{ip}"
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "hostname": data.get("hostname", ""),
                            "current_dns": data.get("current_dns", {}),
                            "alexa_rank": data.get("alexa_rank"),
                            "providers": data.get("providers", [])
                        }
        return None

    async def check_ipqualityscore():
        if api_keys.get("IPQualityScore"):
            async with aiohttp.ClientSession() as session:
                url = f"https://ipqualityscore.com/api/json/ip/{api_keys['IPQualityScore']}/{ip}"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            "proxy": data.get("proxy", False),
                            "vpn": data.get("vpn", False),
                            "tor": data.get("tor", False),
                            "fraud_score": data.get("fraud_score", 0),
                            "country_code": data.get("country_code", ""),
                            "bot_status": data.get("bot_status", False)
                        }
        return None

    tasks = [
        check_virustotal(),
        check_abuseipdb(),
        check_shodan(),
        check_securitytrails(),
        check_ipqualityscore()
    ]

    api_results = await asyncio.gather(*tasks, return_exceptions=True)

    if api_results[0]:
        results["virustotal"] = api_results[0]
    if api_results[1]:
        results["abuseipdb"] = api_results[1]
    if api_results[2]:
        results["shodan"] = api_results[2]
    if api_results[3]:
        results["securitytrails"] = api_results[3]
    if api_results[4]:
        results["ipqualityscore"] = api_results[4]

    return results
