from __future__ import annotations

import pytest

from core.models import (
    APKAnalysis,
    AndroidComponent,
    FoundSecret,
    Permission,
    Severity,
    Vulnerability,
    VulnerabilityCategory,
)


class TestSeverity:
    def test_severity_values(self) -> None:
        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"
        assert Severity.INFO.value == "Info"


class TestVulnerability:
    def test_create_vulnerability(self) -> None:
        v = Vulnerability(
            id="VULN-001",
            title="Test Vulnerability",
            description="Description",
            severity=Severity.HIGH,
            category=VulnerabilityCategory.CODE_QUALITY,
            evidence="test evidence",
        )
        assert v.id == "VULN-001"
        assert v.severity == Severity.HIGH
        assert v.category == VulnerabilityCategory.CODE_QUALITY
        assert v.evidence == "test evidence"

    def test_vulnerability_defaults(self) -> None:
        v = Vulnerability(
            id="VULN-002",
            title="Test",
            description="Desc",
            severity=Severity.LOW,
            category=VulnerabilityCategory.OTHER,
        )
        assert v.owasp_refs == []
        assert v.cwe_refs == []
        assert v.affected_files == []
        assert v.false_positive is False
        assert v.cvss_score is None


class TestAPKAnalysis:
    def test_risk_score_empty(self) -> None:
        analysis = APKAnalysis(file_name="test.apk", file_path="/tmp/test.apk", file_size=100)
        assert analysis.risk_score == 0

    def test_risk_score_with_vulnerabilities(self) -> None:
        analysis = APKAnalysis(file_name="test.apk", file_path="/tmp/test.apk", file_size=100)
        analysis.vulnerabilities = [
            Vulnerability(id="V1", title="T1", description="D1", severity=Severity.CRITICAL, category=VulnerabilityCategory.OTHER),
            Vulnerability(id="V2", title="T2", description="D2", severity=Severity.HIGH, category=VulnerabilityCategory.OTHER),
            Vulnerability(id="V3", title="T3", description="D3", severity=Severity.MEDIUM, category=VulnerabilityCategory.OTHER),
        ]
        assert analysis.risk_score == 12 + 5 + 2

    def test_risk_score_max(self) -> None:
        analysis = APKAnalysis(file_name="test.apk", file_path="/tmp/test.apk", file_size=100)
        analysis.vulnerabilities = [
            Vulnerability(id=f"V{i}", title=f"T{i}", description=f"D{i}", severity=Severity.CRITICAL, category=VulnerabilityCategory.OTHER)
            for i in range(3)
        ] + [
            Vulnerability(id=f"H{i}", title=f"T{i}", description=f"D{i}", severity=Severity.HIGH, category=VulnerabilityCategory.OTHER)
            for i in range(5)
        ] + [
            Vulnerability(id=f"M{i}", title=f"T{i}", description=f"D{i}", severity=Severity.MEDIUM, category=VulnerabilityCategory.OTHER)
            for i in range(10)
        ] + [
            Vulnerability(id=f"L{i}", title=f"T{i}", description=f"D{i}", severity=Severity.LOW, category=VulnerabilityCategory.OTHER)
            for i in range(8)
        ]
        analysis.secrets = [FoundSecret(secret_type="test", value="x", file_path="f", line_number=1, confidence=1.0) for _ in range(11)]
        assert analysis.risk_score == 100

    def test_severity_counts(self) -> None:
        analysis = APKAnalysis(file_name="test.apk", file_path="/tmp/test.apk", file_size=100)
        analysis.vulnerabilities = [
            Vulnerability(id="V1", title="T1", description="D1", severity=Severity.CRITICAL, category=VulnerabilityCategory.OTHER),
            Vulnerability(id="V2", title="T2", description="D2", severity=Severity.CRITICAL, category=VulnerabilityCategory.OTHER),
            Vulnerability(id="V3", title="T3", description="D3", severity=Severity.HIGH, category=VulnerabilityCategory.OTHER),
            Vulnerability(id="V4", title="T4", description="D4", severity=Severity.INFO, category=VulnerabilityCategory.OTHER),
        ]
        counts = analysis.severity_counts
        assert counts["Critical"] == 2
        assert counts["High"] == 1
        assert counts["Info"] == 1

    def test_exported_components(self) -> None:
        analysis = APKAnalysis(file_name="test.apk", file_path="/tmp/test.apk", file_size=100)
        from core.models import ManifestInfo
        analysis.manifest = ManifestInfo(package_name="com.test")
        analysis.manifest.activities = [
            AndroidComponent(name=".MainActivity", component_type="Activity", exported=True),
            AndroidComponent(name=".HiddenActivity", component_type="Activity", exported=False),
        ]
        analysis.manifest.services = [
            AndroidComponent(name=".TestService", component_type="Service", exported=True),
        ]
        exported = analysis.exported_components
        assert len(exported) == 2
        assert all(c.exported for c in exported)

    def test_to_dict(self) -> None:
        analysis = APKAnalysis(file_name="test.apk", file_path="/tmp/test.apk", file_size=100)
        d = analysis.to_dict()
        assert d["file_name"] == "test.apk"
        assert d["risk_score"] == 0
        assert d["vulnerabilities_count"] == 0


class TestAndroidComponent:
    def test_create_component(self) -> None:
        c = AndroidComponent(
            name=".MainActivity",
            component_type="Activity",
            exported=True,
            permission="android.permission.INTERNET",
        )
        assert c.name == ".MainActivity"
        assert c.exported is True
        assert c.permission == "android.permission.INTERNET"


class TestPermission:
    def test_create_permission(self) -> None:
        p = Permission(
            name="android.permission.CAMERA",
            protection_level="Dangerous",
            dangerous=True,
            description="Access camera",
        )
        assert p.name == "android.permission.CAMERA"
        assert p.dangerous is True
