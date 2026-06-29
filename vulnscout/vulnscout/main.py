"""VulnScout CLI -- 基于 Click 的命令行界面."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.panel import Panel

from vulnscout import __version__
from vulnscout.config import VulnScoutConfig
from vulnscout.core.engine import ScanEngine
from vulnscout.detectors import list_available_detectors

console = Console()
error_console = Console(stderr=True)


def _setup_logging(verbose: bool):
    """配置日志."""
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=error_console)],
    )
    # 非 verbose 模式屏蔽 httpx/httpcore 调试日志
    if not verbose:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)


def _render_terminal_report(result):
    """在终端中渲染扫描结果."""
    console.print()
    console.print(Panel.fit(
        f"[bold]VulnScout 扫描报告[/]\n"
        f"目标: {result.target_url}\n"
        f"耗时: {result.scan_duration:.1f}s  |  "
        f"检测器: {len(result.detectors_run)} 个  |  "
        f"漏洞: {result.total_findings} 个",
        border_style="cyan",
    ))

    # 统计摘要
    by_sev = result.by_severity
    summary = Table(show_header=False, box=None, padding=(0, 4))
    summary.add_column("等级", style="bold")
    summary.add_column("数量")
    for sev in ("critical", "high", "medium", "low", "info"):
        count = by_sev.get(sev, 0)
        color = {"critical": "red", "high": "orange3", "medium": "yellow",
                 "low": "blue", "info": "dim"}.get(sev, "")
        style = f"bold {color}" if count > 0 else "dim"
        summary.add_row(f"[{style}]{sev.upper()}[/]", str(count))
    summary.add_row("[bold]总计[/]", str(result.total_findings))
    console.print(summary)

    # Crawler 摘要
    if result.crawl_result:
        console.print()
        cr = result.crawl_result
        console.print(f"[dim]爬取统计: {cr.pages_visited} 页 | "
                      f"{len(cr.endpoints)} 端点 | "
                      f"{len(cr.forms)} 表单 | "
                      f"{len(cr.comments)} 注释[/]")

    # 漏洞列表
    if result.findings:
        console.print()
        table = Table(
            title="漏洞详情",
            box=None,
            header_style="bold",
            show_lines=True,
        )
        table.add_column("等级", width=10, no_wrap=True)
        table.add_column("漏洞", width=30)
        table.add_column("URL", width=50, overflow="fold")
        table.add_column("参数", width=15)
        table.add_column("修复建议", width=40, overflow="fold")

        severity_colors = {
            "critical": "red",
            "high": "orange3",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        for f in result.findings:
            color = severity_colors.get(f.severity.value, "")
            sev_text = f"[bold {color}]{f.severity.value.upper()}[/]"
            table.add_row(
                sev_text,
                f.name,
                f.url,
                f.parameter or "-",
                f.remediation or "-",
            )
        console.print(table)

    # 错误信息
    if result.errors:
        console.print()
        console.print("[yellow]扫描过程中的告警/错误:[/]")
        for err in result.errors[:5]:
            console.print(f"  [dim]- {err}[/]")

    console.print()


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="VulnScout")
def cli():
    """VulnScout -- Web Vulnerability Scanner"""


@cli.command()
@click.argument("url", required=True)
@click.option("--depth", "-d", default=2, help="爬虫深度（默认 2）", type=int)
@click.option("--max-pages", "-m", default=50, help="最大爬取页面数（默认 50）", type=int)
@click.option("--threads", "-t", default=10, help="并发线程数（默认 10）", type=int)
@click.option("--detectors", "-D", default="xss,sqli,headers,sensitive_data",
              help="要启用的检测器，逗号分隔", type=str)
@click.option("--output", "-o", default=None, help="输出报告路径", type=click.Path())
@click.option("--format", "-f", "output_format", default="terminal",
              help="报告格式: html, json, terminal", type=click.Choice(["html", "json", "terminal"]))
@click.option("--proxy", "-p", default=None, help="代理地址 (如 http://127.0.0.1:8080)", type=str)
@click.option("--timeout", default=10.0, help="请求超时秒数（默认 10）", type=float)
@click.option("--crawl/--no-crawl", default=True, help="是否启动爬虫（默认开启）")
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
@click.option("--only-headers", is_flag=True, help="仅检测安全头（快速扫描）")
def scan(
    url: str,
    depth: int,
    max_pages: int,
    threads: int,
    detectors: str,
    output: Optional[str],
    output_format: str,
    proxy: Optional[str],
    timeout: float,
    crawl: bool,
    verbose: bool,
    only_headers: bool,
):
    """扫描目标网站的漏洞.

    URL 为目标网站地址，如 https://example.com
    """
    _setup_logging(verbose)

    detector_list = ["headers"] if only_headers else [d.strip() for d in detectors.split(",")]

    console.print(f"[bold cyan]VulnScout v{__version__}[/]")
    console.print(f"[dim]目标:[/] {url}")
    console.print(f"[dim]检测器:[/] {', '.join(detector_list)}")
    console.print(f"[dim]爬虫深度:[/] {depth}  [dim]线程:[/] {threads}")
    if only_headers:
        console.print("[yellow]快速模式: 仅检测安全头[/]")
    console.print()

    # 构建配置
    config = VulnScoutConfig()
    config.target_url = url
    config.crawler.max_depth = depth
    config.crawler.max_pages = max_pages
    config.scan.threads = threads
    config.scan.enabled_detectors = detector_list
    config.scan.timeout = timeout
    config.scan.proxy = proxy
    config.verbose = verbose

    # 进度显示
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )

    async def _run():
        engine = ScanEngine(config)

        scan_progress = None

        def on_progress(msg, pct):
            nonlocal scan_progress
            if scan_progress is None:
                scan_progress = progress.add_task("", total=100)
            progress.update(scan_progress, description=msg, completed=int(pct * 100))

        engine.on_progress(on_progress)

        with progress:
            result = await engine.run()

        # 终端报告
        _render_terminal_report(result)

        # 文件报告
        if output or output_format != "terminal":
            report_path = output or f"vulnscout_report_{url.replace('://', '_').replace('/', '_')}.{output_format}"
            actual_path = await engine.generate_report(result, output_format, report_path)
            console.print(f"[green][OK] 报告已保存: {actual_path}[/]")

        # 退出码
        if result.has_critical:
            sys.exit(2)
        elif result.has_high:
            sys.exit(1)

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        error_console.print("\n[yellow]扫描被用户中止[/]")
        sys.exit(1)
    except Exception as e:
        error_console.print(f"\n[red]扫描异常: {e}[/]")
        if verbose:
            raise
        sys.exit(1)


@cli.command()
@click.option("--host", default="127.0.0.1", help="监听地址")
@click.option("--port", default=8080, help="监听端口", type=int)
@click.option("--verbose", "-v", is_flag=True, help="详细输出")
def web(host: str, port: int, verbose: bool):
    """启动 Web 管理界面 (FastAPI + HTMX)."""
    _setup_logging(verbose)
    console.print(f"[bold cyan]VulnScout Web UI[/]")
    console.print(f"[dim]启动服务:[/] http://{host}:{port}")
    console.print()

    try:
        from vulnscout.ui.server import run_server
        run_server(host=host, port=port)
    except ImportError as e:
        error_console.print(f"[red]无法启动 Web UI: {e}[/]")
        error_console.print("[yellow]需要安装 web 依赖: pip install 'vulnscout[web]'[/]")
        sys.exit(1)


@cli.command()
@click.option("--output", "-o", default="vulnscout_config.yaml", help="输出路径")
def init(output: str):
    """生成默认配置文件."""
    config_path = Path(output)
    if config_path.exists():
        error_console.print(f"[red]文件已存在: {config_path}[/]")
        sys.exit(1)

    content = """# VulnScout 配置文件
target_url: ""

crawler:
  max_depth: 2
  max_pages: 50
  same_origin_only: true
  respect_robots_txt: true
  extract_forms: true
  extract_scripts: true
  extract_comments: true

scan:
  enabled_detectors:
    - xss
    - sqli
    - headers
    - sensitive_data
  threads: 10
  timeout: 10.0
  random_ua: true

report:
  output_dir: reports
  formats:
    - terminal
"""
    config_path.write_text(content)
    console.print(f"[green][OK] 配置文件已生成: {config_path}[/]")


if __name__ == "__main__":
    cli()
