from __future__ import annotations

from core.models import (
    APKAnalysis,
    AndroidComponent,
    FirebaseConfig,
    FoundSecret,
    FoundURL,
    ManifestInfo,
    NetworkSecurityConfig,
    Permission,
    Severity,
)
from scanner.modules.security_checker import SecurityChecker


class TestSecurityChecker:
    def _make_analysis(self, **kwargs) -> APKAnalysis:
        return APKAnalysis(
            file_name="test.apk",
            file_path="/tmp/test.apk",
            file_size=1000,
            **kwargs,
        )

    def test_debuggable_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test", debuggable=True),
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Debuggable" in t or "debuggable" in t.lower() for t in titles)

    def test_allow_backup_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test", allow_backup=True),
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Backup" in t for t in titles)

    def test_exported_component_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(
                package_name="com.test",
                activities=[
                    AndroidComponent(name=".ExportedActivity", component_type="Activity", exported=True),
                ],
            ),
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Exported" in t for t in titles)

    def test_cleartext_traffic_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test"),
            network_security=NetworkSecurityConfig(cleartext_traffic_allowed=True),
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Cleartext" in t for t in titles)

    def test_dangerous_permissions_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(
                package_name="com.test",
                permissions=[
                    Permission(name="android.permission.CAMERA", protection_level="Dangerous", dangerous=True),
                    Permission(name="android.permission.INTERNET", protection_level="Normal", dangerous=False),
                ],
            ),
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("CAMERA" in t for t in titles)

    def test_hardcoded_secrets_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test"),
            secrets=[
                FoundSecret(
                    secret_type="AWS Access Key ID",
                    value="AKIAIOSFODNN7EXAMPLE",
                    file_path="strings",
                    line_number=1,
                    confidence=0.95,
                ),
            ],
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("AWS" in t or "Secret" in t for t in titles)

    def test_firebase_misconfig_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test"),
            firebase_config=FirebaseConfig(
                present=True,
                api_key="AIzaSyA-test-key",
                misconfigurations=["Firebase API key exposed in application"],
            ),
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Firebase" in t for t in titles)

    def test_api_endpoints_detected(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test"),
            urls=[
                FoundURL(url="https://api.example.com/v1/users", file_path="strings", line_number=1, is_api_endpoint=True),
            ],
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("API" in t for t in titles)

    def test_no_false_positives_for_clean_app(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(
                package_name="com.test",
                debuggable=False,
                allow_backup=False,
                permissions=[
                    Permission(name="android.permission.INTERNET", protection_level="Normal", dangerous=False),
                ],
            ),
            network_security=NetworkSecurityConfig(cleartext_traffic_allowed=False, certificate_pinning=True),
            obfuscated=True,
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        critical_high = [v for v in vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0

    def test_obfuscation_check(self) -> None:
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test"),
            obfuscated=False,
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Obfuscated" in t for t in titles)

    def test_native_libraries_check(self) -> None:
        from core.models import NativeLibrary
        analysis = self._make_analysis(
            manifest=ManifestInfo(package_name="com.test"),
            native_libraries=[
                NativeLibrary(name="libnative.so", path="lib/armeabi-v7a/libnative.so", architectures=["arm32"]),
            ],
        )
        checker = SecurityChecker()
        import asyncio
        vulns = asyncio.run(checker.run(analysis))
        titles = [v.title for v in vulns]
        assert any("Native" in t for t in titles)
