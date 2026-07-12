from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from config.settings import settings
from core.analysis_engine import AnalysisEngine
from core.models import APKAnalysis

logger = logging.getLogger(__name__)

app = FastAPI(
    title="DexRay - APK Security Analyzer",
    description="Static security analysis of Android APK files",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")

scan_results: Dict[str, APKAnalysis] = {}

MAX_UPLOAD_SIZE = settings.max_upload_size
settings.ensure_directories()


@app.on_event("startup")
async def startup() -> None:
    Path(settings.upload_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.output_dir).mkdir(parents=True, exist_ok=True)
    Path(settings.temp_dir).mkdir(parents=True, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    stats = _compute_stats()
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "app_name": settings.app_name,
            "stats": stats,
            "recent_scans": list(scan_results.keys())[-10:],
        },
    )


@app.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_detail(request: Request, scan_id: str) -> HTMLResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Scan not found")
    return templates.TemplateResponse(
        request,
        "scan_detail.html",
        {
            "app_name": settings.app_name,
            "analysis": analysis,
            "scan_id": scan_id,
        },
    )


@app.post("/upload")
async def upload_apk(file: UploadFile = File(...)) -> JSONResponse:
    if not file.filename or not file.filename.endswith(".apk"):
        raise HTTPException(status_code=400, detail="Only .apk files are accepted")

    content = await file.read()
    if len(content) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail=f"File too large. Max: {MAX_UPLOAD_SIZE / 1024 / 1024:.0f} MB")

    scan_id = str(uuid.uuid4())[:8]
    file_path = settings.upload_dir / f"{scan_id}_{file.filename}"
    with open(file_path, "wb") as f:
        f.write(content)

    return JSONResponse({
        "scan_id": scan_id,
        "file_name": file.filename,
        "file_path": str(file_path),
        "size": len(content),
        "message": "File uploaded successfully",
    })


@app.post("/analyze/{scan_id}")
async def analyze_apk(scan_id: str) -> JSONResponse:
    uploads = list(settings.upload_dir.glob(f"{scan_id}_*.apk"))
    if not uploads:
        raise HTTPException(status_code=404, detail="Upload not found")

    file_path = uploads[0]
    engine = AnalysisEngine()

    try:
        analysis = await engine.analyze(str(file_path))
        scan_results[scan_id] = analysis

        report_dir = settings.output_dir / scan_id
        report_dir.mkdir(parents=True, exist_ok=True)

        from reports import JSONReportGenerator, HTMLReportGenerator, PDFReportGenerator

        json_gen = JSONReportGenerator()
        html_gen = HTMLReportGenerator()
        pdf_gen = PDFReportGenerator()

        await json_gen.generate(analysis, str(report_dir / "report.json"))
        await html_gen.generate(analysis, str(report_dir / "report.html"))
        await pdf_gen.generate(analysis, str(report_dir / "report.pdf"))

        return JSONResponse({
            "scan_id": scan_id,
            "status": "completed",
            "risk_score": analysis.risk_score,
            "vulnerabilities": len(analysis.vulnerabilities),
            "secrets": len(analysis.secrets),
            "scan_duration": analysis.scan_duration,
            "report_url": f"/report/{scan_id}",
        })
    except Exception as e:
        logger.exception("Analysis failed")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/status/{scan_id}")
async def scan_status(scan_id: str) -> JSONResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        return JSONResponse({"status": "pending"})
    return JSONResponse({
        "status": "completed",
        "risk_score": analysis.risk_score,
        "total_vulnerabilities": len(analysis.vulnerabilities),
        "severity_counts": analysis.severity_counts,
    })


@app.get("/api/scan/{scan_id}")
async def get_scan_results(scan_id: str) -> JSONResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Scan not found")

    return JSONResponse(analysis.to_dict())


@app.get("/api/scan/{scan_id}/vulnerabilities")
async def get_vulnerabilities(
    scan_id: str,
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
) -> JSONResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = analysis.vulnerabilities
    if severity:
        vulns = [v for v in vulns if v.severity.value == severity]
    if category:
        vulns = [v for v in vulns if v.category.value == category]

    return JSONResponse([
        {
            "id": v.id,
            "title": v.title,
            "severity": v.severity.value,
            "category": v.category.value,
            "description": v.description,
            "evidence": v.evidence,
            "recommendation": v.recommendation,
        }
        for v in vulns
    ])


@app.get("/api/scan/{scan_id}/permissions")
async def get_permissions(scan_id: str) -> JSONResponse:
    analysis = scan_results.get(scan_id)
    if not analysis or not analysis.manifest:
        raise HTTPException(status_code=404, detail="Scan not found")

    return JSONResponse([
        {"name": p.name, "dangerous": p.dangerous, "protection_level": p.protection_level}
        for p in analysis.manifest.permissions
    ])


@app.get("/api/scan/{scan_id}/secrets")
async def get_secrets(scan_id: str) -> JSONResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse([
        {"type": s.secret_type, "value": s.value[:50], "confidence": s.confidence}
        for s in analysis.secrets
    ])


@app.get("/api/scan/{scan_id}/urls")
async def get_urls(scan_id: str) -> JSONResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Scan not found")
    return JSONResponse([
        {"url": u.url, "is_api": u.is_api_endpoint}
        for u in analysis.urls
    ])


@app.get("/report/{scan_id}")
async def view_report(scan_id: str) -> HTMLResponse:
    analysis = scan_results.get(scan_id)
    if not analysis:
        raise HTTPException(status_code=404, detail="Report not found")
    html_report = settings.output_dir / scan_id / "report.html"
    if html_report.exists():
        return HTMLResponse(content=html_report.read_text())
    return HTMLResponse(content="<h1>Report not generated yet</h1>")


@app.get("/download/{scan_id}/{format}")
async def download_report(scan_id: str, format: str) -> FileResponse:
    file_map = {
        "json": "report.json",
        "html": "report.html",
        "pdf": "report.pdf",
    }
    filename = file_map.get(format)
    if not filename:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

    report_path = settings.output_dir / scan_id / filename
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        str(report_path),
        media_type="application/octet-stream",
        filename=f"apk_security_report.{format}",
    )


@app.get("/api/scans")
async def list_scans() -> JSONResponse:
    return JSONResponse([
        {
            "scan_id": sid,
            "file_name": a.file_name,
            "risk_score": a.risk_score,
            "vulnerability_count": len(a.vulnerabilities),
            "timestamp": a.scan_timestamp.isoformat(),
        }
        for sid, a in scan_results.items()
    ])


@app.get("/api/stats")
async def get_stats() -> JSONResponse:
    return JSONResponse(_compute_stats())


def _compute_stats() -> Dict[str, Any]:
    total_scans = len(scan_results)
    total_vulns = sum(len(a.vulnerabilities) for a in scan_results.values())
    total_secrets = sum(len(a.secrets) for a in scan_results.values())
    avg_score = sum(a.risk_score for a in scan_results.values()) / max(total_scans, 1)

    severity_dist: Dict[str, int] = {}
    for a in scan_results.values():
        for sev, count in a.severity_counts.items():
            severity_dist[sev] = severity_dist.get(sev, 0) + count

    return {
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "total_secrets": total_secrets,
        "average_risk_score": round(avg_score, 1),
        "severity_distribution": severity_dist,
    }
