"""Web UI -- FastAPI 异步服务."""

from __future__ import annotations

import asyncio
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Form, Request, Query
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse

from vulnscout import __version__
from vulnscout.config import VulnScoutConfig
from vulnscout.core.engine import ScanEngine

# 扫描历史 (内存存储, 生产环境应改用 DB)
scan_history: list = []

app = FastAPI(title="VulnScout Web UI", version=__version__)

# 模板目录
templates_dir = Path(__file__).parent / "templates"
static_dir = Path(__file__).parent / "static"


def _render_template(name: str, **context) -> str:
    """渲染 Jinja2 模板（手工处理兼容性问题）."""
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    env = Environment(
        loader=FileSystemLoader(str(templates_dir)),
        autoescape=select_autoescape(["html", "xml"]),
        # 禁用缓存以避免 Jinja2 3.1.6+ 兼容性问题
        cache_size=0,
    )
    template = env.get_template(name)
    return template.render(**context)


@app.on_event("startup")
async def startup():
    templates_dir.mkdir(parents=True, exist_ok=True)
    static_dir.mkdir(parents=True, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, started: bool = Query(False)):
    """首页 -- 扫描仪表盘."""
    html = _render_template(
        "index.html",
        version=__version__,
        scans=scan_history[-10:][::-1],
        scan_started=started,
    )
    return HTMLResponse(html)


@app.post("/scan")
async def scan_form(
    url: str = Form(...),
    depth: int = Form(2),
    max_pages: int = Form(50),
    detectors: str = Form("xss,sqli,headers,sensitive_data"),
):
    """Web 表单提交 -- 启动扫描后重定向回首页."""
    config = VulnScoutConfig()
    config.target_url = url
    config.crawler.max_depth = depth
    config.crawler.max_pages = max_pages
    config.scan.enabled_detectors = [d.strip() for d in detectors.split(",")]

    scan_id = f"scan_{int(time.time())}"
    scan_record = {
        "id": scan_id,
        "url": url,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": 0,
        "duration": 0,
        "report_path": "",
    }
    scan_history.append(scan_record)

    async def _run_scan():
        try:
            engine = ScanEngine(config)
            result = await engine.run()

            report_dir = Path(tempfile.gettempdir()) / "vulnscout_reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"{scan_id}.html"
            await engine.generate_report(result, "html", str(report_path))

            scan_record.update(
                status="completed" if not result.has_critical else "warning",
                findings=result.total_findings,
                duration=round(result.scan_duration, 1),
                report_path=str(report_path),
                summary=result.by_severity,
            )
        except Exception as e:
            scan_record.update(status="error", error=str(e))

    asyncio.create_task(_run_scan())

    return RedirectResponse(url="/?started=1", status_code=303)


@app.post("/api/scan")
async def api_start_scan(
    url: str = Form(...),
    depth: int = Form(2),
    max_pages: int = Form(50),
    detectors: str = Form("xss,sqli,headers,sensitive_data"),
):
    """启动扫描."""
    config = VulnScoutConfig()
    config.target_url = url
    config.crawler.max_depth = depth
    config.crawler.max_pages = max_pages
    config.scan.enabled_detectors = [d.strip() for d in detectors.split(",")]

    scan_id = f"scan_{int(time.time())}"
    scan_record = {
        "id": scan_id,
        "url": url,
        "status": "running",
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": 0,
        "duration": 0,
        "report_path": "",
    }
    scan_history.append(scan_record)

    async def _run_scan():
        try:
            engine = ScanEngine(config)
            result = await engine.run()

            # 生成 HTML 报告
            report_dir = Path(tempfile.gettempdir()) / "vulnscout_reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / f"{scan_id}.html"
            await engine.generate_report(result, "html", str(report_path))

            # 更新记录
            scan_record.update(
                status="completed" if not result.has_critical else "warning",
                findings=result.total_findings,
                duration=round(result.scan_duration, 1),
                report_path=str(report_path),
                summary=result.by_severity,
            )
        except Exception as e:
            scan_record.update(
                status="error",
                findings=0,
                duration=0,
                error=str(e),
            )

    asyncio.create_task(_run_scan())

    return {"scan_id": scan_id, "status": "started"}


@app.get("/api/scan/{scan_id}")
async def api_scan_status(scan_id: str):
    """获取扫描状态."""
    for scan in scan_history:
        if scan["id"] == scan_id:
            return scan
    return {"error": "not found"}


@app.get("/api/scans")
async def api_list_scans():
    """扫描历史列表."""
    return scan_history[-20:][::-1]


@app.get("/report/{scan_id}")
async def view_report(scan_id: str):
    """查看扫描报告 HTML."""
    for scan in scan_history:
        if scan["id"] == scan_id and scan.get("report_path"):
            report_path = scan["report_path"]
            if os.path.exists(report_path):
                return FileResponse(report_path, media_type="text/html")
    return HTMLResponse("<h2>Report not available</h2>", status_code=404)


def run_server(host: str = "127.0.0.1", port: int = 8080):
    """启动 Web 服务."""
    import uvicorn
    uvicorn.run(app, host=host, port=port, log_level="info")
