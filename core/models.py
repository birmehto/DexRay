from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class VulnerabilityCategory(str, Enum):
    HARDCODED_SECRETS = "Hardcoded Secrets"
    INSECURE_STORAGE = "Insecure Storage"
    EXPORTED_COMPONENTS = "Exported Components"
    WEAK_CRYPTOGRAPHY = "Weak Cryptography"
    NETWORK_SECURITY = "Network Security"
    WEBVIEW_VULNERABILITIES = "WebView Vulnerabilities"
    DANGEROUS_PERMISSIONS = "Dangerous Permissions"
    CODE_QUALITY = "Code Quality"
    CONFIGURATION_ISSUES = "Configuration Issues"
    PLATFORM_MISUSE = "Platform Misuse"
    API_ISSUES = "API Issues"
    FIREBASE_MISCONFIGURATION = "Firebase Misconfiguration"
    CERTIFICATE_ISSUES = "Certificate Issues"
    NATIVE_CODE_ISSUES = "Native Code Issues"
    OBFUSCATION_ISSUES = "Obfuscation Issues"
    LOGGING_ISSUES = "Logging Issues"
    THIRD_PARTY = "Third Party Libraries"
    OTHER = "Other"


@dataclass
class Vulnerability:
    id: str
    title: str
    description: str
    severity: Severity
    category: VulnerabilityCategory
    owasp_refs: List[str] = field(default_factory=list)
    cwe_refs: List[str] = field(default_factory=list)
    masvs_refs: List[str] = field(default_factory=list)
    evidence: Optional[str] = None
    affected_files: List[str] = field(default_factory=list)
    recommendation: Optional[str] = None
    cvss_score: Optional[float] = None
    false_positive: bool = False
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Permission:
    name: str
    protection_level: Optional[str] = None
    dangerous: bool = False
    description: Optional[str] = None
    used_by_features: List[str] = field(default_factory=list)


@dataclass
class AndroidComponent:
    name: str
    component_type: str
    exported: bool = False
    permission: Optional[str] = None
    intent_filters: List[Dict[str, Any]] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CertificateInfo:
    subject: Optional[str] = None
    issuer: Optional[str] = None
    serial_number: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    md5_fingerprint: Optional[str] = None
    algorithm: Optional[str] = None
    is_valid: bool = True
    issues: List[str] = field(default_factory=list)


@dataclass
class NetworkSecurityConfig:
    cleartext_traffic_allowed: bool = False
    certificate_pinning: bool = False
    debug_overrides: bool = False
    config_file: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FoundSecret:
    secret_type: str
    value: str
    file_path: str
    line_number: int
    confidence: float
    context: Optional[str] = None


@dataclass
class FoundURL:
    url: str
    file_path: str
    line_number: int
    is_api_endpoint: bool = False
    context: Optional[str] = None


@dataclass
class NativeLibrary:
    name: str
    path: str
    architectures: List[str] = field(default_factory=list)
    exported_functions: List[str] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class FirebaseConfig:
    present: bool = False
    api_key: Optional[str] = None
    project_id: Optional[str] = None
    database_url: Optional[str] = None
    storage_bucket: Optional[str] = None
    messaging_sender_id: Optional[str] = None
    app_id: Optional[str] = None
    misconfigurations: List[str] = field(default_factory=list)


@dataclass
class ManifestInfo:
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    debuggable: bool = False
    allow_backup: bool = False
    test_only: bool = False
    has_network_security_config: bool = False
    large_heap: bool = False
    extract_native_libs: bool = True
    supports_renderscript: bool = False
    permissions: List[Permission] = field(default_factory=list)
    activities: List[AndroidComponent] = field(default_factory=list)
    services: List[AndroidComponent] = field(default_factory=list)
    receivers: List[AndroidComponent] = field(default_factory=list)
    providers: List[AndroidComponent] = field(default_factory=list)
    metadata: Dict[str, str] = field(default_factory=dict)
    raw_xml: Optional[str] = None


@dataclass
class EnvVariable:
    key: str
    value: str
    file_path: str
    line_number: int = 0
    is_sensitive: bool = False


@dataclass
class DeepLinkInfo:
    scheme: str
    host: Optional[str] = None
    path: Optional[str] = None
    path_prefix: Optional[str] = None
    path_pattern: Optional[str] = None
    is_app_link: bool = False
    is_verified: bool = False
    component: Optional[str] = None


@dataclass
class BuildConfigInfo:
    compile_sdk: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    build_tools_version: Optional[str] = None
    has_minify_enabled: bool = False
    has_debuggable_build: bool = False
    signing_configs: List[str] = field(default_factory=list)
    build_types: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    plugins: List[str] = field(default_factory=list)
    raw_config: Optional[str] = None


@dataclass
class TrackingSDK:
    name: str
    category: str
    evidence: str


@dataclass
class DebugTool:
    name: str
    library: str
    evidence: str


@dataclass
class APKAnalysis:
    file_name: str
    file_path: str
    file_size: int
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    manifest: Optional[ManifestInfo] = None
    certificates: List[CertificateInfo] = field(default_factory=list)
    network_security: Optional[NetworkSecurityConfig] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    secrets: List[FoundSecret] = field(default_factory=list)
    urls: List[FoundURL] = field(default_factory=list)
    native_libraries: List[NativeLibrary] = field(default_factory=list)
    firebase_config: Optional[FirebaseConfig] = None
    assets: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    obfuscated: bool = False
    third_party_libraries: List[str] = field(default_factory=list)
    java_packages: List[str] = field(default_factory=list)
    env_variables: List[EnvVariable] = field(default_factory=list)
    deep_links: List[DeepLinkInfo] = field(default_factory=list)
    build_config: Optional[BuildConfigInfo] = None
    tracking_sdks: List[TrackingSDK] = field(default_factory=list)
    debug_tools: List[DebugTool] = field(default_factory=list)
    apk_signer_version: Optional[str] = None
    scan_duration: float = 0.0
    scan_timestamp: datetime = field(default_factory=datetime.now)
    tools_used: List[str] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        if not self.vulnerabilities:
            return 0
        counts = self.severity_counts
        crit = min(counts.get(Severity.CRITICAL.value, 0), 3) * 12
        high = min(counts.get(Severity.HIGH.value, 0), 5) * 5
        med = min(counts.get(Severity.MEDIUM.value, 0), 10) * 2
        low = min(counts.get(Severity.LOW.value, 0), 8) * 1
        secrets = min(len(self.secrets), 11)
        total = crit + high + med + low + secrets
        return min(100, total)

    @property
    def severity_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for s in Severity:
            counts[s.value] = 0
        for v in self.vulnerabilities:
            if v.severity.value in counts:
                counts[v.severity.value] += 1
        return counts

    @property
    def category_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for v in self.vulnerabilities:
            counts[v.category.value] = counts.get(v.category.value, 0) + 1
        return counts

    @property
    def exported_components(self) -> List[AndroidComponent]:
        exported: List[AndroidComponent] = []
        if self.manifest:
            for comp in (
                self.manifest.activities
                + self.manifest.services
                + self.manifest.receivers
                + self.manifest.providers
            ):
                if comp.exported:
                    exported.append(comp)
        return exported

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_name": self.file_name,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha256": self.sha256,
            "package_name": self.manifest.package_name if self.manifest else None,
            "risk_score": self.risk_score,
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "vulnerabilities_count": len(self.vulnerabilities),
            "secrets_count": len(self.secrets),
            "urls_count": len(self.urls),
            "exported_components_count": len(self.exported_components),
            "native_libraries_count": len(self.native_libraries),
            "scan_duration": self.scan_duration,
            "scan_timestamp": self.scan_timestamp.isoformat(),
        }
