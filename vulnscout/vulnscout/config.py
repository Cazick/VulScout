"""VulnScout 配置管理 -- 支持环境变量、配置文件、CLI 参数."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import yaml


@dataclass
class CrawlerConfig:
    """爬虫配置."""

    max_depth: int = 2
    max_pages: int = 50
    same_origin_only: bool = True
    respect_robots_txt: bool = True
    extract_forms: bool = True
    extract_scripts: bool = True
    extract_comments: bool = True


@dataclass
class ScanConfig:
    """扫描配置."""

    enabled_detectors: List[str] = field(
        default_factory=lambda: ["xss", "sqli", "headers", "sensitive_data"]
    )
    threads: int = 10
    timeout: float = 10.0
    max_redirects: int = 5
    retry_count: int = 2
    random_ua: bool = True
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    proxy: Optional[str] = None
    delay: float = 0.0  # 请求间隔（秒）


@dataclass
class ReportConfig:
    """报告配置."""

    output_dir: str = "reports"
    formats: List[str] = field(default_factory=lambda: ["terminal"])
    open_browser: bool = False


@dataclass
class VulnScoutConfig:
    """全局配置."""

    target_url: str = ""
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    report: ReportConfig = field(default_factory=ReportConfig)
    verbose: bool = False

    @classmethod
    def from_dict(cls, data: dict) -> VulnScoutConfig:
        """从字典加载配置."""
        config = cls()

        if "target_url" in data:
            config.target_url = data["target_url"]
        if "verbose" in data:
            config.verbose = data["verbose"]

        if "crawler" in data:
            c = data["crawler"]
            config.crawler = CrawlerConfig(
                max_depth=c.get("max_depth", config.crawler.max_depth),
                max_pages=c.get("max_pages", config.crawler.max_pages),
                same_origin_only=c.get("same_origin_only", config.crawler.same_origin_only),
                respect_robots_txt=c.get("respect_robots_txt", config.crawler.respect_robots_txt),
                extract_forms=c.get("extract_forms", config.crawler.extract_forms),
                extract_scripts=c.get("extract_scripts", config.crawler.extract_scripts),
                extract_comments=c.get("extract_comments", config.crawler.extract_comments),
            )

        if "scan" in data:
            s = data["scan"]
            config.scan = ScanConfig(
                enabled_detectors=s.get("enabled_detectors", config.scan.enabled_detectors),
                threads=s.get("threads", config.scan.threads),
                timeout=s.get("timeout", config.scan.timeout),
                max_redirects=s.get("max_redirects", config.scan.max_redirects),
                retry_count=s.get("retry_count", config.scan.retry_count),
                random_ua=s.get("random_ua", config.scan.random_ua),
                cookies=s.get("cookies", config.scan.cookies),
                headers=s.get("headers", config.scan.headers),
                proxy=s.get("proxy", config.scan.proxy),
                delay=s.get("delay", config.scan.delay),
            )

        return config

    @classmethod
    def from_file(cls, path: str) -> VulnScoutConfig:
        """从 YAML 文件加载配置."""
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    def merge_cli(self, **kwargs) -> VulnScoutConfig:
        """合并 CLI 参数到配置中（非 None 值覆盖）. """
        for key, value in kwargs.items():
            if value is not None:
                if hasattr(self.crawler, key):
                    setattr(self.crawler, key, value)
                elif hasattr(self.scan, key):
                    setattr(self.scan, key, value)
                elif hasattr(self.report, key):
                    setattr(self.report, key, value)
                elif hasattr(self, key):
                    setattr(self, key, value)
        return self
