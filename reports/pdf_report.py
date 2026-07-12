from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from core.models import APKAnalysis
from reports.base import ReportGenerator

logger = logging.getLogger(__name__)


class PDFReportGenerator(ReportGenerator):
    async def generate(self, analysis: APKAnalysis, output_path: str) -> str:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.platypus import (
                SimpleDocTemplate,
                Paragraph,
                Spacer,
                Table,
                TableStyle,
                PageBreak,
                HRFlowable,
            )
        except ImportError:
            logger.warning("reportlab not installed, falling back to text report")
            return await self._generate_fallback(analysis, output_path)

        doc = SimpleDocTemplate(
            str(output),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Title"],
            fontSize=24,
            spaceAfter=30,
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading1"],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
        )
        normal_style = ParagraphStyle(
            "CustomNormal",
            parent=styles["Normal"],
            fontSize=10,
            leading=14,
        )
        code_style = ParagraphStyle(
            "CodeStyle",
            parent=styles["Code"],
            fontSize=8,
            leading=10,
        )

        elements: list = []

        elements.append(Paragraph("APK Security Analysis Report", title_style))
        elements.append(Paragraph(f"Generated: {analysis.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        elements.append(Paragraph(f"File: {analysis.file_name}", normal_style))
        elements.append(Paragraph(f"Package: {analysis.manifest.package_name if analysis.manifest else 'N/A'}", normal_style))
        elements.append(Spacer(1, 0.25 * inch))

        elements.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
        elements.append(Spacer(1, 0.25 * inch))

        risk_color = colors.red if analysis.risk_score >= 50 else (colors.orange if analysis.risk_score >= 30 else colors.green)
        elements.append(Paragraph(f"Risk Score: <font color='{risk_color.hexval() if hasattr(risk_color, 'hexval') else 'red'}'><b>{analysis.risk_score}/100</b></font>", heading_style))

        severity_data = [["Severity", "Count"]]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            severity_data.append([sev, str(analysis.severity_counts.get(sev, 0))])
        t = Table(severity_data, colWidths=[2 * inch, 1 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.25 * inch))

        if analysis.manifest:
            elements.append(Paragraph("Application Information", heading_style))
            app_info = [
                ["Package", analysis.manifest.package_name],
                ["Version", analysis.manifest.version_name or "N/A"],
                ["Min SDK", str(analysis.manifest.min_sdk or "N/A")],
                ["Target SDK", str(analysis.manifest.target_sdk or "N/A")],
                ["Debuggable", str(analysis.manifest.debuggable)],
                ["Allow Backup", str(analysis.manifest.allow_backup)],
                ["File Size", f"{analysis.file_size / 1024 / 1024:.2f} MB"],
            ]
            t = Table(app_info, colWidths=[2 * inch, 4 * inch])
            t.setStyle(TableStyle([
                ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]))
            elements.append(t)
            elements.append(Spacer(1, 0.25 * inch))

        elements.append(Paragraph(f"Vulnerabilities ({len(analysis.vulnerabilities)})", heading_style))
        if analysis.vulnerabilities:
            for v in analysis.vulnerabilities:
                elements.append(Paragraph(f"<b>{v.id}: {v.title}</b>  <font color='red'>{v.severity.value}</font>", normal_style))
                elements.append(Paragraph(f"<i>{v.description}</i>", normal_style))
                if v.evidence:
                    elements.append(Paragraph(f"Evidence: {v.evidence}", code_style))
                if v.recommendation:
                    elements.append(Paragraph(f"Fix: {v.recommendation}", normal_style))
                elements.append(Spacer(1, 0.1 * inch))
        else:
            elements.append(Paragraph("No vulnerabilities found.", normal_style))

        elements.append(PageBreak())

        elements.append(Paragraph(f"Secrets Found ({len(analysis.secrets)})", heading_style))
        if analysis.secrets:
            secret_data = [["Type", "Confidence"]]
            for s in analysis.secrets[:30]:
                secret_data.append([s.secret_type, f"{s.confidence:.0%}"])
            t = Table(secret_data, colWidths=[4 * inch, 1 * inch])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 1, colors.lightgrey),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
            ]))
            elements.append(t)
        else:
            elements.append(Paragraph("No secrets detected.", normal_style))

        elements.append(Spacer(1, 0.25 * inch))
        elements.append(Paragraph(f"API Endpoints Found ({len([u for u in analysis.urls if u.is_api_endpoint])})", heading_style))
        for u in analysis.urls:
            if u.is_api_endpoint:
                elements.append(Paragraph(f"• {u.url}", code_style))

        elements.append(Spacer(1, 0.25 * inch))
        elements.append(Paragraph("Recommendations", heading_style))
        if analysis.manifest and analysis.manifest.debuggable:
            elements.append(Paragraph("• Set android:debuggable=false in AndroidManifest.xml", normal_style))
        if analysis.manifest and analysis.manifest.allow_backup:
            elements.append(Paragraph("• Disable backup unless required", normal_style))
        if analysis.secrets:
            elements.append(Paragraph(f"• Remove {len(analysis.secrets)} hardcoded secrets", normal_style))

        doc.build(elements)
        return str(output)

    async def _generate_fallback(self, analysis: APKAnalysis, output_path: str) -> str:
        output = Path(output_path)
        with open(output, "w", encoding="utf-8") as f:
            f.write(f"APK Security Analysis Report\n")
            f.write(f"{'=' * 40}\n\n")
            f.write(f"File: {analysis.file_name}\n")
            f.write(f"Package: {analysis.manifest.package_name if analysis.manifest else 'N/A'}\n")
            f.write(f"Risk Score: {analysis.risk_score}/100\n")
            f.write(f"Vulnerabilities: {len(analysis.vulnerabilities)}\n")
            f.write(f"Secrets: {len(analysis.secrets)}\n\n")
            for v in analysis.vulnerabilities:
                f.write(f"[{v.severity.value}] {v.title}\n")
                f.write(f"  {v.description}\n\n")
        return str(output)
