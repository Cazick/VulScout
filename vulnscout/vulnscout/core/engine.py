"""Scanner Engine -- 核心扫描引擎，统筹爬虫、检测器、报告器."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Type

from vulnscout.config import VulnScoutConfig
from vulnscout.core.crawler import Crawler, CrawlResult
from vulnscout.core.http_client import HttpClient
from vulnscout.detectors import (
    BaseDetector,
    Finding,
    ScanContext,
    get_all_detectors,
    list_available_detectors,
)
from vulnscout.reporter import BaseReporter, Report
from vulnscout.reporter.html_reporter import HTMLReporter
from vulnscout.reporter.json_reporter import JSONReporter

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """一次完整扫描的结果."""

    target_url: str
    findings: List[Finding] = field(default_factory=list)
    crawl_result: Optional[CrawlResult] = None
    scan_duration: float = 0.0
    detectors_run: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for f in self.findings:
            key = f.severity.value
            result[key] = result.get(key, 0) + 1
        return result

    @property
    def has_critical(self) -> bool:
        return any(f.severity.value == "critical" for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity.value == "high" for f in self.findings)


class ScanEngine:
    """扫描引擎 -- 统筹爬虫 → 检测器 → 报告的全流程."""

    def __init__(self, config: VulnScoutConfig):
        self._config = config
        self._progress_callback = None

    def on_progress(self, callback):
        """设置进度回调."""
        self._progress_callback = callback

    def _report_progress(self, message: str, progress: float = 0):
        """报告进度."""
        if self._progress_callback:
            self._progress_callback(message, progress)

    async def run(self) -> ScanResult:
        """执行一次完整扫描."""
        start_time = time.time()
        result = ScanResult(target_url=self._config.target_url)
        errors: List[str] = []

        self._report_progress("初始化 HTTP 客户端...", 0.05)

        async with HttpClient(
            timeout=self._config.scan.timeout,
            proxy=self._config.scan.proxy,
            cookies=self._config.scan.cookies,
            headers=self._config.scan.headers,
            random_ua=self._config.scan.random_ua,
            retry_count=self._config.scan.retry_count,
            delay=self._config.scan.delay,
        ) as http:

            # ---- Phase 1: 爬取 ----
            crawl_result = None
            if self._config.crawler.max_pages > 0:
                self._report_progress("阶段 1/3: 爬取目标...", 0.1)
                try:
                    crawler = Crawler(
                        http_client=http,
                        max_depth=self._config.crawler.max_depth,
                        max_pages=self._config.crawler.max_pages,
                        same_origin_only=self._config.crawler.same_origin_only,
                        extract_forms=self._config.crawler.extract_forms,
                        extract_scripts=self._config.crawler.extract_scripts,
                        extract_comments=self._config.crawler.extract_comments,
                    )
                    crawl_result = await crawler.crawl(self._config.target_url)
                    result.crawl_result = crawl_result
                    self._report_progress(
                        f"爬取完成: {crawl_result.pages_visited} 页, "
                        f"{len(crawl_result.endpoints)} 端点, "
                        f"{len(crawl_result.forms)} 表单",
                        0.35,
                    )
                except Exception as e:
                    error_msg = f"爬取失败: {e}"
                    logger.exception(error_msg)
                    errors.append(error_msg)
                    self._report_progress(f"爬取出错: {e}", 0.35)
            else:
                self._report_progress("跳过爬取阶段", 0.35)

            # ---- Phase 2: 检测 ----
            self._report_progress("阶段 2/3: 执行漏洞检测...", 0.4)

            # 构建 ScanContext
            context = ScanContext(
                target_url=self._config.target_url,
                endpoints=[ep.__dict__ if hasattr(ep, '__dict__') else ep
                          for ep in (crawl_result.endpoints if crawl_result else [])],
                forms=[f.__dict__ if hasattr(f, '__dict__') else f
                       for f in (crawl_result.forms if crawl_result else [])],
                html_comments=crawl_result.comments if crawl_result else [],
            )

            # 加载检测器
            detector_names = self._config.scan.enabled_detectors
            all_detectors = get_all_detectors()

            for det_name in detector_names:
                det_class = all_detectors.get(det_name)
                if not det_class:
                    errors.append(f"检测器 '{det_name}' 未找到，可用: {list_available_detectors()}")
                    continue

                try:
                    detector: BaseDetector = det_class(
                        http_client=http,
                        config={"timeout": self._config.scan.timeout},
                    )
                    detector_name = getattr(detector, 'name', det_name)
                    result.detectors_run.append(detector_name)
                    self._report_progress(f"  运行 {detector_name} 检测器...", 0.4)

                    findings = await detector.detect(context)
                    result.findings.extend(findings)

                    logger.info(
                        "%s 检测器完成: 发现 %d 个漏洞",
                        detector_name, len(findings)
                    )
                except Exception as e:
                    error_msg = f"{det_name} 检测器异常: {e}"
                    logger.exception(error_msg)
                    errors.append(error_msg)

            self._report_progress("漏洞检测完成", 0.8)

            # ---- Phase 3: 去重与报告 ----
            self._report_progress("阶段 3/3: 生成报告...", 0.85)

            # 去重
            result.findings = self._deduplicate_findings(result.findings)

            # 按严重等级排序
            severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            result.findings.sort(key=lambda f: severity_order.get(f.severity.value, 99))

        # 计算耗时
        result.scan_duration = time.time() - start_time
        result.errors = errors

        self._report_progress(
            f"扫描完成! 发现 {len(result.findings)} 个漏洞, "
            f"耗时 {result.scan_duration:.1f}s",
            1.0,
        )

        return result

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """对发现的漏洞进行去重."""
        seen: set = set()
        unique = []
        for f in findings:
            # 用 name + url + param 作为唯一键
            key = f"{f.name}:{f.url}:{f.parameter}:{f.payload}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    async def generate_report(
        self,
        scan_result: ScanResult,
        output_format: str = "terminal",
        output_path: Optional[str] = None,
    ) -> str:
        """生成扫描报告."""
        report = Report(
            target_url=scan_result.target_url,
            findings=scan_result.findings,
            scan_summary={
                "scan_duration": scan_result.scan_duration,
                "detectors_run": scan_result.detectors_run,
                "pages_visited": scan_result.crawl_result.pages_visited
                if scan_result.crawl_result else 0,
                "endpoints_found": len(scan_result.crawl_result.endpoints)
                if scan_result.crawl_result else 0,
                "forms_found": len(scan_result.crawl_result.forms)
                if scan_result.crawl_result else 0,
                "total_findings": len(scan_result.findings),
                "by_severity": scan_result.by_severity,
            },
            scan_duration=scan_result.scan_duration,
        )

        if output_format == "html":
            reporter = HTMLReporter()
        elif output_format == "json":
            reporter = JSONReporter()
        else:
            return ""  # terminal 由 CLI 直接处理

        return reporter.generate(report, output_path or "")
