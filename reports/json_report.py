from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.models import APKAnalysis, Severity
from reports.base import ReportGenerator


class JSONReportGenerator(ReportGenerator):
    async def generate(self, analysis: APKAnalysis, output_path: str) -> str:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        report = self._build_report(analysis)
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        return str(output)

    def _build_report(self, analysis: APKAnalysis) -> Dict[str, Any]:
        return {
            "report_metadata": {
                "title": "APK Security Analysis Report",
                "generated_at": analysis.scan_timestamp.isoformat(),
                "scan_duration_seconds": round(analysis.scan_duration, 2),
                "tools_used": analysis.tools_used,
            },
            "application_info": {
                "file_name": analysis.file_name,
                "file_size_bytes": analysis.file_size,
                "hashes": {
                    "md5": analysis.md5,
                    "sha1": analysis.sha1,
                    "sha256": analysis.sha256,
                },
                "package_name": analysis.manifest.package_name if analysis.manifest else None,
                "version_name": analysis.manifest.version_name if analysis.manifest else None,
                "version_code": analysis.manifest.version_code if analysis.manifest else None,
                "min_sdk": analysis.manifest.min_sdk if analysis.manifest else None,
                "target_sdk": analysis.manifest.target_sdk if analysis.manifest else None,
            },
            "risk_assessment": {
                "risk_score": analysis.risk_score,
                "severity_summary": analysis.severity_counts,
                "total_vulnerabilities": len(analysis.vulnerabilities),
                "risk_level": self._risk_level(analysis.risk_score),
            },
            "manifest_analysis": self._manifest_report(analysis),
            "vulnerabilities": self._vulnerabilities_to_dicts(analysis),
            "secrets": [
                {
                    "type": s.secret_type,
                    "value_truncated": s.value[:50] + "..." if len(s.value) > 50 else s.value,
                    "confidence": s.confidence,
                }
                for s in analysis.secrets
            ],
            "network_security": self._network_report(analysis),
            "certificates": [
                {
                    "subject": c.subject,
                    "issuer": c.issuer,
                    "valid_from": c.valid_from,
                    "valid_to": c.valid_to,
                    "sha256": c.sha256_fingerprint,
                    "issues": c.issues,
                }
                for c in analysis.certificates
            ],
            "firebase_configuration": {
                "present": analysis.firebase_config.present if analysis.firebase_config else False,
                "misconfigurations": analysis.firebase_config.misconfigurations if analysis.firebase_config else [],
            } if analysis.firebase_config else {"present": False},
            "native_libraries": [
                {
                    "name": lib.name,
                    "architectures": lib.architectures,
                }
                for lib in analysis.native_libraries
            ],
            "api_endpoints": [
                {"url": u.url, "file": u.file_path}
                for u in analysis.urls if u.is_api_endpoint
            ],
            "urls_found": [
                {"url": u.url}
                for u in analysis.urls
            ],
            "recommendations": self._generate_recommendations(analysis),
        }

    def _manifest_report(self, analysis: APKAnalysis) -> Dict[str, Any]:
        if not analysis.manifest:
            return {}
        return {
            "package_name": analysis.manifest.package_name,
            "debuggable": analysis.manifest.debuggable,
            "allow_backup": analysis.manifest.allow_backup,
            "permissions": [
                {
                    "name": p.name,
                    "dangerous": p.dangerous,
                    "protection_level": p.protection_level,
                    "description": p.description,
                }
                for p in analysis.manifest.permissions
            ],
            "activities": self._components_list(analysis.manifest.activities),
            "services": self._components_list(analysis.manifest.services),
            "receivers": self._components_list(analysis.manifest.receivers),
            "providers": self._components_list(analysis.manifest.providers),
            "exported_components": [
                {"name": c.name, "type": c.component_type}
                for c in analysis.exported_components
            ],
        }

    def _components_list(self, components: list) -> list:
        return [
            {
                "name": c.name,
                "exported": c.exported,
                "permission": c.permission,
                "intent_filters": c.intent_filters,
            }
            for c in components
        ]

    def _network_report(self, analysis: APKAnalysis) -> Dict[str, Any]:
        if not analysis.network_security:
            return {}
        return {
            "cleartext_traffic_allowed": analysis.network_security.cleartext_traffic_allowed,
            "certificate_pinning": analysis.network_security.certificate_pinning,
            "debug_overrides": analysis.network_security.debug_overrides,
        }

    def _risk_level(self, score: int) -> str:
        if score >= 70:
            return "Critical"
        elif score >= 50:
            return "High"
        elif score >= 30:
            return "Medium"
        elif score >= 10:
            return "Low"
        return "Info"

    def _generate_recommendations(self, analysis: APKAnalysis) -> list:
        recs = []
        critical = [v for v in analysis.vulnerabilities if v.severity == Severity.CRITICAL]
        high = [v for v in analysis.vulnerabilities if v.severity == Severity.HIGH]

        if critical:
            recs.append({
                "priority": "Immediate",
                "text": f"Address {len(critical)} critical vulnerabilities: " + "; ".join(v.title for v in critical[:3]),
            })
        if high:
            recs.append({
                "priority": "High",
                "text": f"Address {len(high)} high severity issues.",
            })
        if analysis.secrets:
            recs.append({
                "priority": "High",
                "text": f"Remove {len(analysis.secrets)} hardcoded secrets from the application.",
            })
        if analysis.firebase_config and analysis.firebase_config.present:
            recs.append({
                "priority": "Medium",
                "text": "Review Firebase security rules and ensure databases are properly secured.",
            })

        return recs
