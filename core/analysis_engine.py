from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict

from config.settings import settings
from core.models import APKAnalysis

logger = logging.getLogger(__name__)


def compute_hashes(file_path: str) -> Dict[str, str]:
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


class AnalysisEngine:
    def __init__(self) -> None:
        settings.ensure_directories()

    async def analyze(self, apk_path: str) -> APKAnalysis:
        start_time = time.time()
        file_path = Path(apk_path)
        if not file_path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        hashes = compute_hashes(apk_path)
        analysis = APKAnalysis(
            file_name=file_path.name,
            file_path=str(file_path.absolute()),
            file_size=file_path.stat().st_size,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
        )

        phase1 = [
            self._extract_manifest(analysis),
            self._extract_certificates(analysis),
            self._scan_strings(analysis),
            self._scan_native_libraries(analysis),
            self._scan_assets(analysis),
            self._scan_env(analysis),
            self._scan_build_config(analysis),
            self._scan_apk_signer(analysis),
        ]
        await asyncio.gather(*phase1, return_exceptions=True)

        phase2 = [
            self._extract_network_config(analysis),
            self._scan_firebase(analysis),
            self._scan_urls(analysis),
            self._scan_secrets(analysis),
            self._scan_deep_links(analysis),
            self._scan_debug_tools(analysis),
            self._scan_tracking_sdks(analysis),
            self._audit_permissions(analysis),
        ]
        await asyncio.gather(*phase2, return_exceptions=True)

        await self._run_security_checks(analysis)

        analysis.scan_duration = time.time() - start_time
        return analysis

    async def _extract_manifest(self, analysis: APKAnalysis) -> None:
        from scanner.modules.manifest_scanner import ManifestScanner
        scanner = ManifestScanner()
        manifest = await scanner.extract(analysis.file_path)
        analysis.manifest = manifest

    async def _extract_certificates(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.certificate_scanner import CertificateScanner
            scanner = CertificateScanner()
            certs = await scanner.extract(analysis.file_path)
            analysis.certificates = certs
        except Exception as e:
            logger.warning("Certificate extraction failed: %s", e)

    async def _extract_network_config(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.network_config_scanner import NetworkConfigScanner
            scanner = NetworkConfigScanner()
            config = await scanner.extract(analysis.file_path, analysis.manifest)
            analysis.network_security = config
        except Exception as e:
            logger.warning("Network config extraction failed: %s", e)

    async def _scan_strings(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.strings_scanner import StringsScanner
            scanner = StringsScanner()
            analysis.strings = await scanner.extract(analysis.file_path)
        except Exception as e:
            logger.warning("String extraction failed: %s", e)

    async def _scan_native_libraries(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.native_scanner import NativeLibraryScanner
            scanner = NativeLibraryScanner()
            analysis.native_libraries = await scanner.extract(analysis.file_path)
        except Exception as e:
            logger.warning("Native library scan failed: %s", e)

    async def _scan_assets(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.asset_scanner import AssetScanner
            scanner = AssetScanner()
            analysis.assets = await scanner.extract(analysis.file_path)
        except Exception as e:
            logger.warning("Asset scan failed: %s", e)

    async def _scan_firebase(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.firebase_scanner import FirebaseScanner
            scanner = FirebaseScanner()
            analysis.firebase_config = await scanner.extract(analysis.file_path, analysis.strings)
        except Exception as e:
            logger.warning("Firebase scan failed: %s", e)

    async def _scan_urls(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.url_scanner import URLScanner
            scanner = URLScanner()
            analysis.urls = await scanner.extract(analysis.file_path, analysis.strings)
        except Exception as e:
            logger.warning("URL scan failed: %s", e)

    async def _scan_secrets(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.secret_scanner import SecretScanner
            scanner = SecretScanner()
            analysis.secrets = await scanner.extract(analysis.file_path, analysis.strings)
        except Exception as e:
            logger.warning("Secret scan failed: %s", e)

    async def _scan_env(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.env_scanner import EnvScanner
            scanner = EnvScanner()
            analysis.env_variables = await scanner.scan(analysis.file_path)
        except Exception as e:
            logger.warning("Env scan failed: %s", e)

    async def _scan_build_config(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.build_config_scanner import BuildConfigScanner
            scanner = BuildConfigScanner()
            analysis.build_config = await scanner.scan(analysis.file_path)
        except Exception as e:
            logger.warning("Build config scan failed: %s", e)

    async def _scan_deep_links(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.deep_link_scanner import DeepLinkScanner
            scanner = DeepLinkScanner()
            analysis.deep_links = await scanner.scan(analysis.file_path, analysis.strings)
        except Exception as e:
            logger.warning("Deep link scan failed: %s", e)

    async def _scan_debug_tools(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.debug_tools_scanner import DebugToolsScanner
            scanner = DebugToolsScanner()
            analysis.debug_tools = await scanner.scan(analysis.file_path, analysis.strings)
        except Exception as e:
            logger.warning("Debug tools scan failed: %s", e)

    async def _scan_tracking_sdks(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.tracking_scanner import TrackingScanner
            scanner = TrackingScanner()
            analysis.tracking_sdks = await scanner.scan(analysis.file_path, analysis.strings)
        except Exception as e:
            logger.warning("Tracking SDK scan failed: %s", e)

    async def _scan_apk_signer(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.apk_signer_scanner import APKSignerScanner
            scanner = APKSignerScanner()
            analysis.apk_signer_version = await scanner.scan(analysis.file_path)
        except Exception as e:
            logger.warning("APK signer scan failed: %s", e)

    async def _audit_permissions(self, analysis: APKAnalysis) -> None:
        if not analysis.manifest:
            return
        try:
            from scanner.modules.permission_audit_scanner import PermissionAuditScanner
            scanner = PermissionAuditScanner()
            findings = await scanner.audit(analysis.manifest)
            analysis.vulnerabilities.extend(findings)
        except Exception as e:
            logger.warning("Permission audit failed: %s", e)

    async def _run_security_checks(self, analysis: APKAnalysis) -> None:
        try:
            from scanner.modules.security_checker import SecurityChecker
            checker = SecurityChecker()
            findings = await checker.run(analysis)
            analysis.vulnerabilities.extend(findings)
        except Exception as e:
            logger.warning("Security checks failed: %s", e)
