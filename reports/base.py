from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from core.models import APKAnalysis


class ReportGenerator(ABC):
    def __init__(self) -> None:
        self.output_dir = Path("/tmp/apk-analyzer/reports")

    @abstractmethod
    async def generate(self, analysis: APKAnalysis, output_path: str) -> str:
        ...

    def _vulnerabilities_to_dicts(self, analysis: APKAnalysis) -> List[Dict[str, Any]]:
        return [
            {
                "id": v.id,
                "title": v.title,
                "description": v.description,
                "severity": v.severity.value,
                "category": v.category.value,
                "owasp_refs": v.owasp_refs,
                "cwe_refs": v.cwe_refs,
                "masvs_refs": v.masvs_refs,
                "evidence": v.evidence,
                "affected_files": v.affected_files,
                "recommendation": v.recommendation,
                "cvss_score": v.cvss_score,
            }
            for v in analysis.vulnerabilities
        ]
