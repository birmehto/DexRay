from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from core.models import APKAnalysis, Severity, Vulnerability, VulnerabilityCategory
from reports.html_report import HTMLReportGenerator
from reports.json_report import JSONReportGenerator


class TestJSONReport:
    @pytest.mark.asyncio
    async def test_generate_json_report(self) -> None:
        analysis = APKAnalysis(
            file_name="test.apk",
            file_path="/tmp/test.apk",
            file_size=1000,
            scan_duration=1.5,
        )
        analysis.vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="Test Issue",
                description="Test description",
                severity=Severity.HIGH,
                category=VulnerabilityCategory.CODE_QUALITY,
                evidence="Evidence here",
                recommendation="Fix it",
                owasp_refs=["M1"],
                cwe_refs=["CWE-1"],
            ),
        ]

        generator = JSONReportGenerator()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            output_path = f.name

        try:
            result = await generator.generate(analysis, output_path)
            assert Path(result).exists()

            with open(result) as f:
                data = json.load(f)

            assert data["application_info"]["file_name"] == "test.apk"
            assert data["risk_assessment"]["risk_score"] == 5
            assert len(data["vulnerabilities"]) == 1
            assert data["vulnerabilities"][0]["id"] == "VULN-001"
            assert data["vulnerabilities"][0]["severity"] == "High"
        finally:
            Path(output_path).unlink(missing_ok=True)


class TestHTMLReport:
    @pytest.mark.asyncio
    async def test_generate_html_report(self) -> None:
        analysis = APKAnalysis(
            file_name="test.apk",
            file_path="/tmp/test.apk",
            file_size=1000,
        )
        analysis.vulnerabilities = [
            Vulnerability(
                id="VULN-001",
                title="Test Issue",
                description="Test description",
                severity=Severity.CRITICAL,
                category=VulnerabilityCategory.CODE_QUALITY,
            ),
        ]

        generator = HTMLReportGenerator()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f:
            output_path = f.name

        try:
            result = await generator.generate(analysis, output_path)
            assert Path(result).exists()

            with open(result) as f:
                content = f.read()

            assert "APK Security Analysis Report" in content
            assert "Test Issue" in content
            assert "Critical" in content
        finally:
            Path(output_path).unlink(missing_ok=True)
