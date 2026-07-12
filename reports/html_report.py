from __future__ import annotations

from pathlib import Path
from core.models import APKAnalysis
from reports.base import ReportGenerator

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK Security Analysis Report</title>
<style>
:root {{
  --critical: #dc2626;
  --high: #ea580c;
  --medium: #ca8a04;
  --low: #2563eb;
  --info: #6b7280;
  --bg: #f8fafc;
  --card: #ffffff;
  --border: #e2e8f0;
  --text: #1e293b;
  --text-muted: #64748b;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
.header {{ background: linear-gradient(135deg, #1e293b, #334155); color: white; padding: 3rem 2rem; border-radius: 16px; margin-bottom: 2rem; }}
.header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
.header .meta {{ color: #94a3b8; font-size: 0.9rem; }}
.score-container {{ display: flex; align-items: center; gap: 2rem; margin-top: 1.5rem; }}
.score-ring {{ width: 120px; height: 120px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: bold; border: 6px solid; flex-shrink: 0; }}
.score-ring.critical {{ border-color: var(--critical); color: var(--critical); }}
.score-ring.high {{ border-color: var(--high); color: var(--high); }}
.score-ring.medium {{ border-color: var(--medium); color: var(--medium); }}
.score-ring.low {{ border-color: var(--low); color: var(--low); }}
.score-ring.info {{ border-color: var(--info); color: var(--info); }}
.score-details {{ flex: 1; }}
.score-details .stat {{ display: flex; justify-content: space-between; padding: 0.25rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); }}
.card {{ background: var(--card); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid var(--border); }}
.card h2 {{ font-size: 1.25rem; margin-bottom: 1rem; color: var(--text); border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; }}
.grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
.grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1.5rem; }}
.stat-box {{ text-align: center; padding: 1rem; }}
.stat-box .number {{ font-size: 2rem; font-weight: bold; }}
.stat-box .label {{ color: var(--text-muted); font-size: 0.85rem; }}
.severity-bar {{ display: flex; height: 24px; border-radius: 12px; overflow: hidden; margin: 1rem 0; }}
.severity-bar .segment {{ transition: width 0.3s; }}
.severity-tag {{ display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }}
.severity-tag.Critical {{ background: #fef2f2; color: var(--critical); }}
.severity-tag.High {{ background: #fff7ed; color: var(--high); }}
.severity-tag.Medium {{ background: #fefce8; color: var(--medium); }}
.severity-tag.Low {{ background: #eff6ff; color: var(--low); }}
.severity-tag.Info {{ background: #f3f4f6; color: var(--info); }}
.vuln-item {{ padding: 1rem; border: 1px solid var(--border); border-radius: 8px; margin-bottom: 0.75rem; }}
.vuln-item:last-child {{ margin-bottom: 0; }}
.vuln-header {{ display: flex; justify-content: space-between; align-items: start; margin-bottom: 0.5rem; }}
.vuln-title {{ font-weight: 600; }}
.vuln-desc {{ color: var(--text-muted); font-size: 0.9rem; margin-bottom: 0.5rem; }}
.vuln-meta {{ font-size: 0.8rem; color: var(--text-muted); }}
.vuln-meta span {{ margin-right: 1rem; }}
.evidence {{ background: #f1f5f9; padding: 0.75rem; border-radius: 6px; font-family: 'SF Mono', Monaco, monospace; font-size: 0.8rem; margin-top: 0.5rem; white-space: pre-wrap; overflow-x: auto; }}
.recommendation {{ background: #f0fdf4; border-left: 3px solid #22c55e; padding: 0.75rem; border-radius: 0 6px 6px 0; margin-top: 0.5rem; font-size: 0.9rem; }}
.permission-list {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
.permission-badge {{ background: #f1f5f9; padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.8rem; }}
.permission-badge.dangerous {{ background: #fef2f2; color: var(--critical); }}
.secret-item {{ display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
.url-item {{ font-size: 0.85rem; font-family: 'SF Mono', monospace; padding: 0.25rem 0; color: var(--text-muted); }}
.recommendation-card {{ background: #f0fdf4; border-left: 4px solid #22c55e; padding: 1rem; margin-bottom: 0.75rem; border-radius: 0 8px 8px 0; }}
.recommendation-card .priority {{ font-weight: 600; color: #16a34a; font-size: 0.85rem; text-transform: uppercase; }}
.app-info-table {{ width: 100%; border-collapse: collapse; }}
.app-info-table td {{ padding: 0.5rem; border-bottom: 1px solid var(--border); }}
.app-info-table td:first-child {{ font-weight: 600; color: var(--text-muted); width: 180px; }}
.section-nav {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
.section-nav a {{ color: var(--text-muted); text-decoration: none; padding: 0.5rem 1rem; border: 1px solid var(--border); border-radius: 8px; font-size: 0.85rem; transition: all 0.2s; }}
.section-nav a:hover {{ background: var(--card); border-color: var(--text); color: var(--text); }}
@media (max-width: 768px) {{ .grid-2, .grid-3 {{ grid-template-columns: 1fr; }} .score-container {{ flex-direction: column; text-align: center; }} .header {{ padding: 2rem 1rem; }} .container {{ padding: 1rem; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>APK Security Analysis Report</h1>
    <div class="meta">
      <span>Generated: {generated_at}</span> |
      <span>Duration: {duration}s</span> |
      <span>Tools: {tools}</span>
    </div>
    <div class="score-container">
      <div class="score-ring {risk_class}">{risk_score}</div>
      <div class="score-details">
        <div class="stat"><span>Risk Level</span><span>{risk_level}</span></div>
        <div class="stat"><span>Total Vulnerabilities</span><span>{total_vulns}</span></div>
        <div class="stat"><span>Package</span><span>{package_name}</span></div>
        <div class="stat"><span>File</span><span>{file_name}</span></div>
      </div>
    </div>
  </div>

  <div class="section-nav">
    <a href="#summary">Summary</a>
    <a href="#manifest">Manifest</a>
    <a href="#vulnerabilities">Vulnerabilities</a>
    <a href="#permissions">Permissions</a>
    <a href="#secrets">Secrets</a>
    <a href="#network">Network</a>
    <a href="#recommendations">Recommendations</a>
  </div>

  <div id="summary" class="card">
    <h2>Severity Distribution</h2>
    <div class="severity-bar">{severity_bar}</div>
    <div class="grid-3">{severity_stats}</div>
  </div>

  <div class="grid-2">
    <div class="card">
      <h2>Application Info</h2>
      <table class="app-info-table">{app_info_rows}</table>
    </div>
    <div class="card" id="permissions">
      <h2>Permissions ({permission_count})</h2>
      <div class="permission-list">{permission_badges}</div>
    </div>
  </div>

  <div id="vulnerabilities" class="card">
    <h2>Vulnerabilities ({total_vulns})</h2>
    {vulnerability_list}
  </div>

  <div class="grid-2">
    <div class="card" id="secrets">
      <h2>Secrets Found ({secret_count})</h2>
      {secret_list}
    </div>
    <div class="card" id="network">
      <h2>Network Security</h2>
      {network_info}
    </div>
  </div>

  <div class="card" id="recommendations">
    <h2>Recommendations</h2>
    {recommendation_list}
  </div>

  <div class="card">
    <h2>Certificates</h2>
    {certificate_info}
  </div>

  <div class="card">
    <h2>Native Libraries</h2>
    {native_info}
  </div>

  <div class="card">
    <h2>API Endpoints & URLs</h2>
    {url_info}
  </div>
</div>
</body>
</html>
"""


class HTMLReportGenerator(ReportGenerator):
    async def generate(self, analysis: APKAnalysis, output_path: str) -> str:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        risk_class = self._risk_class(analysis.risk_score)

        context = {
            "generated_at": analysis.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "duration": f"{analysis.scan_duration:.2f}",
            "tools": ", ".join(analysis.tools_used),
            "risk_score": analysis.risk_score,
            "risk_class": risk_class,
            "risk_level": self._risk_level(analysis.risk_score),
            "total_vulns": len(analysis.vulnerabilities),
            "package_name": analysis.manifest.package_name if analysis.manifest else "N/A",
            "file_name": analysis.file_name,
            "severity_bar": self._severity_bar(analysis),
            "severity_stats": self._severity_stats(analysis),
            "app_info_rows": self._app_info_rows(analysis),
            "permission_count": len(analysis.manifest.permissions) if analysis.manifest else 0,
            "permission_badges": self._permission_badges(analysis),
            "vulnerability_list": self._vulnerability_list(analysis),
            "secret_count": len(analysis.secrets),
            "secret_list": self._secret_list(analysis),
            "network_info": self._network_info(analysis),
            "recommendation_list": self._recommendation_list(analysis),
            "certificate_info": self._certificate_info(analysis),
            "native_info": self._native_info(analysis),
            "url_info": self._url_info(analysis),
        }

        html = HTML_TEMPLATE.format(**context)
        with open(output, "w", encoding="utf-8") as f:
            f.write(html)

        return str(output)

    def _risk_class(self, score: int) -> str:
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        elif score >= 10:
            return "low"
        return "info"

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

    def _severity_bar(self, analysis: APKAnalysis) -> str:
        counts = analysis.severity_counts
        total = max(sum(counts.values()), 1)
        colors = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb", "Info": "#6b7280"}
        segments = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            pct = (counts.get(sev, 0) / total) * 100
            if pct > 0:
                segments.append(f'<div class="segment" style="width:{pct}%;background:{colors[sev]}"></div>')
        return "".join(segments)

    def _severity_stats(self, analysis: APKAnalysis) -> str:
        counts = analysis.severity_counts
        items = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            items.append(f'<div class="stat-box"><div class="number" style="color:{self._sev_color(sev)}">{counts.get(sev, 0)}</div><div class="label">{sev}</div></div>')
        return "".join(items)

    def _sev_color(self, severity: str) -> str:
        colors = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#ca8a04", "Low": "#2563eb", "Info": "#6b7280"}
        return colors.get(severity, "#6b7280")

    def _app_info_rows(self, analysis: APKAnalysis) -> str:
        rows = [
            ("Package", analysis.manifest.package_name if analysis.manifest else "N/A"),
            ("Version", analysis.manifest.version_name if analysis.manifest else "N/A"),
            ("Min SDK", str(analysis.manifest.min_sdk) if analysis.manifest and analysis.manifest.min_sdk else "N/A"),
            ("Target SDK", str(analysis.manifest.target_sdk) if analysis.manifest and analysis.manifest.target_sdk else "N/A"),
            ("File Size", f"{analysis.file_size / 1024 / 1024:.2f} MB"),
            ("MD5", analysis.md5 or "N/A"),
            ("SHA256", (analysis.sha256 or "N/A")[:32] + "..."),
            ("Debuggable", str(analysis.manifest.debuggable) if analysis.manifest else "N/A"),
            ("Allow Backup", str(analysis.manifest.allow_backup) if analysis.manifest else "N/A"),
            ("Obfuscated", str(analysis.obfuscated)),
            ("Native Libs", str(len(analysis.native_libraries))),
        ]
        return "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows)

    def _permission_badges(self, analysis: APKAnalysis) -> str:
        if not analysis.manifest:
            return "<p>No permissions found</p>"
        badges = []
        for p in analysis.manifest.permissions:
            cls = "dangerous" if p.dangerous else ""
            short = p.name.split(".")[-1].replace("_", " ")
            badges.append(f'<span class="permission-badge {cls}" title="{p.name}">{short}</span>')
        return "".join(badges) if badges else "<p>No permissions declared</p>"

    def _vulnerability_list(self, analysis: APKAnalysis) -> str:
        items = []
        for v in analysis.vulnerabilities:
            sev = v.severity.value
            items.append(f"""
            <div class="vuln-item">
              <div class="vuln-header">
                <span class="vuln-title">{v.id}: {v.title}</span>
                <span class="severity-tag {sev}">{sev}</span>
              </div>
              <div class="vuln-desc">{v.description}</div>
              <div class="vuln-meta">
                <span>Category: {v.category.value}</span>
                {''.join(f'<span>OWASP: {ref}</span>' for ref in v.owasp_refs[:2])}
                {''.join(f'<span>CWE: {ref}</span>' for ref in v.cwe_refs[:2])}
              </div>
              {f'<div class="evidence">{v.evidence}</div>' if v.evidence else ''}
              {f'<div class="recommendation">{v.recommendation}</div>' if v.recommendation else ''}
            </div>""")
        return "".join(items) if items else "<p>No vulnerabilities found</p>"

    def _secret_list(self, analysis: APKAnalysis) -> str:
        items = []
        for s in analysis.secrets[:20]:
            items.append(f'<div class="secret-item"><span>{s.secret_type}</span><span style="color:var(--text-muted)">confidence: {s.confidence:.0%}</span></div>')
        if not items:
            return "<p>No secrets found</p>"
        if len(analysis.secrets) > 20:
            items.append(f'<div class="secret-item">... and {len(analysis.secrets) - 20} more</div>')
        return "".join(items)

    def _network_info(self, analysis: APKAnalysis) -> str:
        ns = analysis.network_security
        if not ns:
            return "<p>No network security configuration found</p>"
        items = [
            f"<tr><td>Cleartext Traffic</td><td>{'⚠️ Allowed' if ns.cleartext_traffic_allowed else '✓ Blocked'}</td></tr>",
            f"<tr><td>Certificate Pinning</td><td>{'✓ Present' if ns.certificate_pinning else '✗ Not configured'}</td></tr>",
            f"<tr><td>Debug Overrides</td><td>{'⚠️ Present' if ns.debug_overrides else '✓ None'}</td></tr>",
        ]
        return f"<table class='app-info-table'>{''.join(items)}</table>"

    def _recommendation_list(self, analysis: APKAnalysis) -> str:
        items = []
        if analysis.manifest and analysis.manifest.debuggable:
            items.append('<div class="recommendation-card"><div class="priority">Critical</div>Set android:debuggable=false before release</div>')
        if analysis.network_security and analysis.network_security.cleartext_traffic_allowed:
            items.append('<div class="recommendation-card"><div class="priority">High</div>Disable cleartext traffic, enforce HTTPS</div>')
        if analysis.secrets:
            items.append(f'<div class="recommendation-card"><div class="priority">High</div>Remove {len(analysis.secrets)} hardcoded secrets</div>')
        if analysis.manifest and analysis.manifest.allow_backup:
            items.append('<div class="recommendation-card"><div class="priority">Medium</div>Disable backup unless required</div>')
        items.append('<div class="recommendation-card"><div class="priority">Info</div>Enable obfuscation with ProGuard/R8</div>')
        return "".join(items) if items else "<p>No specific recommendations</p>"

    def _certificate_info(self, analysis: APKAnalysis) -> str:
        if not analysis.certificates:
            return "<p>No certificate information</p>"
        items = []
        for c in analysis.certificates:
            items.append(f"""<div class="vuln-item">
              <div class="vuln-header"><span class="vuln-title">Subject: {c.subject or 'N/A'}</span></div>
              <div class="vuln-meta">
                <span>Issuer: {c.issuer or 'N/A'}</span>
                <span>Algorithm: {c.algorithm or 'N/A'}</span>
                <span>Valid: {c.valid_from or '?'} → {c.valid_to or '?'}</span>
              </div>
            </div>""")
        return "".join(items)

    def _native_info(self, analysis: APKAnalysis) -> str:
        if not analysis.native_libraries:
            return "<p>No native libraries found</p>"
        items = [f'<div class="url-item">{lib.name} ({", ".join(lib.architectures)})</div>' for lib in analysis.native_libraries]
        return "".join(items)

    def _url_info(self, analysis: APKAnalysis) -> str:
        api_urls = [u for u in analysis.urls if u.is_api_endpoint]
        all_urls = analysis.urls
        items = []
        items.append(f"<p><strong>API Endpoints:</strong> {len(api_urls)}</p>")
        for u in api_urls[:10]:
            items.append(f'<div class="url-item">🔗 {u.url[:100]}</div>')
        items.append(f"<p style='margin-top:1rem'><strong>Total URLs:</strong> {len(all_urls)}</p>")
        return "".join(items)
