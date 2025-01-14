from enum import Enum, IntEnum, auto
from typing import Dict, Set, List, Any, Final
import sys
from cryptography.hazmat.primitives import hashes

VERSION: Final[str] = "1.0.0-beta"
DEFAULT_TIMEOUT: Final[int] = 30
MAX_RETRIES: Final[int] = 3
RATE_LIMIT: Final[int] = 100
CACHE_TTL: Final[int] = 7200
RETRY_DELAY: Final[float] = 0.5
PARTIAL_RESULTS_THRESHOLD = 0.7

QUANTUM_RESISTANT_ALGORITHMS = {
    'CRYSTALS-Kyber': ['kyber512', 'kyber768', 'kyber1024'],
    'SPHINCS+': ['sphincs-sha256-128f', 'sphincs-sha256-192f'],
    'Dilithium': ['dilithium2', 'dilithium3', 'dilithium5'],
    'Falcon': ['falcon512', 'falcon1024']
}

MODERN_HASH_ALGORITHMS = {
    'SHA3-256': hashes.SHA3_256(),
    'SHA3-384': hashes.SHA3_384(),
    'SHA3-512': hashes.SHA3_512(),
    'BLAKE2b': hashes.BLAKE2b(64),
    'BLAKE2s': hashes.BLAKE2s(32)
}

class PortCategory(IntEnum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()

class ModernPortCategory(IntEnum):
    QUANTUM = auto()
    BLOCKCHAIN = auto()
    CONTAINER = auto()
    MICROSERVICE = auto()

class DangerousPort(IntEnum):
    TELNET = 23
    TFTP = 69
    SMB = 445
    RDP = 3389

DANGEROUS_PORTS: Dict[int, str] = {
    port.value: port.name for port in DangerousPort
}

HIGH_RISK_PORTS: Set[int] = {21, 25, 53, 3306, 5432}

MODERN_SERVICE_PORTS: Dict[ModernPortCategory, Set[int]] = {
    ModernPortCategory.QUANTUM: {1234, 4321},
    ModernPortCategory.BLOCKCHAIN: {8545, 8546},
    ModernPortCategory.CONTAINER: {2375, 2376},
    ModernPortCategory.MICROSERVICE: {8080, 8081, 8082}
}

class ShadowsocksEncryptionMethod(Enum):
    STRONG = 'strong'
    MEDIUM = 'medium'
    WEAK = 'weak'

SHADOWSOCKS_COMMON_PORTS: Set[int] = {443, 8388, 8389, 1080, 1081, 8080, 8443}

SHADOWSOCKS_ENCRYPTION_METHODS: Dict[str, Set[str]] = {
    ShadowsocksEncryptionMethod.STRONG.value: {'aes-256-gcm', 'chacha20-ietf-poly1305', 'xchacha20-ietf-poly1305'},
    ShadowsocksEncryptionMethod.MEDIUM.value: {'aes-128-gcm', 'aes-256-cfb', 'aes-128-cfb', 'chacha20-ietf'},
    ShadowsocksEncryptionMethod.WEAK.value: {'rc4-md5', 'bf-cfb', 'des-cfb', 'rc4'}
}

class EncryptionStrength(Enum):
    QUANTUM_RESISTANT = 'quantum_resistant'
    VERY_STRONG = 'very_strong'
    STRONG = 'strong'
    MEDIUM = 'medium'
    WEAK = 'weak'

class V2RayEncryptionMethod(Enum):
    STRONG = 'strong'
    MEDIUM = 'medium'
    WEAK = 'weak'

V2RAY_ENCRYPTION_METHODS: Dict[str, Set[str]] = {
    EncryptionStrength.QUANTUM_RESISTANT.value: {'kyber-1024', 'ntru-hps-4096'},
    EncryptionStrength.VERY_STRONG.value: {'chacha20-poly1305', 'aes-256-gcm'},
    EncryptionStrength.STRONG.value: {'aes-128-gcm', 'chacha20-poly1305'},
    EncryptionStrength.MEDIUM.value: {'auto'},
    EncryptionStrength.WEAK.value: {'none'}
}

V2RAY_SECURE_PORTS: Set[int] = {443, 8443, 2053, 2083}
V2RAY_COMMON_PORTS: Set[int] = {80, 443, 8080, 8443}

class NmapScanType(Enum):
    BASIC = 'basic'
    AGGRESSIVE = 'aggressive'
    VULNERABILITY = 'vulnerability'
    FULL = 'full'

NMAP_SCAN_TYPES: Dict[str, str] = {
    scan_type.value: params for scan_type, params in zip(
        NmapScanType,
        ['-sS -sV', '-A', '--script vuln', '-sS -sV -O -A']
    )
}

NMAP_SCRIPT_CATEGORIES: List[str] = [
    'auth',
    'vuln',
    'exploit',
    'brute',
    'discovery',
]

class AvailableAPI(str, Enum):
    VIRUSTOTAL = "VirusTotal"
    ABUSEIPDB = "AbuseIPDB"
    SHODAN = "Shodan"
    SECURITYTRAILS = "SecurityTrails"
    IPQUALITYSCORE = "IPQualityScore"

AVAILABLE_APIS = {api.value: {"required": False} for api in AvailableAPI}

def validate_ports():
    overlap = HIGH_RISK_PORTS & set(DANGEROUS_PORTS.keys())
    if overlap:
        print(f"Overlapping ports detected: {overlap}", file=sys.stderr)
        sys.exit(1)

validate_ports()
