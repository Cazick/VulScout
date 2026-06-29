"""Sensitive Data Disclosure Detector -- 敏感信息泄露检测."""

from __future__ import annotations

import logging
import re
from typing import List, Pattern

from vulnscout.detectors.base import (
    BaseDetector,
    Confidence,
    Finding,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)

# 敏感信息正则模式
SENSITIVE_PATTERNS: List[dict] = [
    # API 密钥 / Token
    {
        "name": "API Key / Token",
        "pattern": re.compile(
            r'(?:(?:api[_-]?)?key\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,64}["\']?)',
            re.I,
        ),
        "severity": Severity.CRITICAL,
        "description": "可能的 API 密钥或 Token 泄露",
        "cwe": "CWE-798",
    },
    {
        "name": "AWS Access Key",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
        "severity": Severity.CRITICAL,
        "description": "AWS Access Key ID 泄露",
        "cwe": "CWE-798",
    },
    {
        "name": "AWS Secret Key",
        "pattern": re.compile(r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
        "severity": Severity.CRITICAL,
        "description": "AWS Secret Access Key 泄露",
        "cwe": "CWE-798",
    },
    {
        "name": "GitHub Token",
        "pattern": re.compile(r'ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'),
        "severity": Severity.CRITICAL,
        "description": "GitHub Token 泄露",
        "cwe": "CWE-798",
    },
    {
        "name": "Google OAuth Key",
        "pattern": re.compile(r'(?i)AIza[0-9A-Za-z\-_]{35}'),
        "severity": Severity.CRITICAL,
        "description": "Google API/OAuth 密钥泄露",
        "cwe": "CWE-798",
    },
    {
        "name": "JWT Token",
        "pattern": re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
        "severity": Severity.HIGH,
        "description": "JWT Token 泄露",
        "cwe": "CWE-312",
    },
    {
        "name": "Generic Secret",
        "pattern": re.compile(
            r'(?i)(?:secret|password|passwd|pwd|token|auth)[\s]*[:=][\s]*["\']?[A-Za-z0-9_\-!@#$%^&*]{8,}["\']?'
        ),
        "severity": Severity.HIGH,
        "description": "可能的密码或密钥硬编码",
        "cwe": "CWE-798",
    },
    # 内部路径 / 技术栈暴露
    {
        "name": "内部路径泄露",
        "pattern": re.compile(
            r'(?:/var/www/|/home/|/root/|C:\\Users\\|/app/|/opt/)[A-Za-z0-9_\-/]+',
            re.I,
        ),
        "severity": Severity.MEDIUM,
        "description": "服务器内部路径泄露，有助于攻击者了解目录结构",
        "cwe": "CWE-200",
    },
    {
        "name": "框架版本暴露",
        "pattern": re.compile(
            r'(?:Django|Flask|Express|Spring|Laravel|Rails|ASP\.NET)\s*[0-9]+\.[0-9]+',
            re.I,
        ),
        "severity": Severity.LOW,
        "description": "Web 框架版本号泄露，攻击者可针对已知漏洞发起攻击",
        "cwe": "CWE-200",
    },
    {
        "name": "服务器信息泄露",
        "pattern": re.compile(r'(?:Server|X-Powered-By):\s*.+', re.I),
        "severity": Severity.LOW,
        "description": "服务器/技术栈信息泄露",
        "cwe": "CWE-200",
    },
    # 数据库连接字符串
    {
        "name": "数据库连接串",
        "pattern": re.compile(
            r'(?:mysql|postgres|sqlite|mongodb|redis)://[A-Za-z0-9_\-]+:[^@]+@',
            re.I,
        ),
        "severity": Severity.CRITICAL,
        "description": "数据库连接字符串泄露，可能导致数据库被未授权访问",
        "cwe": "CWE-798",
    },
    # 注释中的 TODO / FIXME / HACK
    {
        "name": "开发者注释",
        "pattern": re.compile(r'(?:TODO|FIXME|HACK|XXX|BUG|WORKAROUND)\s*[:：].*', re.I),
        "severity": Severity.LOW,
        "description": "HTML 注释中包含开发者标记，可能泄露开发信息",
        "cwe": "CWE-200",
    },
    # 内网 IP
    {
        "name": "内网 IP 地址",
        "pattern": re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
        "severity": Severity.MEDIUM,
        "description": "内网 IP 地址泄露，有助于攻击者了解内部网络结构",
        "cwe": "CWE-200",
    },
    # Email 地址
    {
        "name": "Email 地址",
        "pattern": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'),
        "severity": Severity.LOW,
        "description": "Email 地址泄露",
        "cwe": "CWE-200",
    },
]

# 通用 HTML 注释正则 -- 不需要额外扫描，爬虫已提取注释


class SensitiveDataDetector(BaseDetector):
    """敏感信息泄露检测器.

    扫描 HTML 内容、注释、响应头中的敏感信息模式，
    包括 API Key、密码、内网 IP、数据库连接串等.
    """

    name = "sensitive_data"
    description = "敏感信息泄露检测 -- API Key / 密码 / 内网 IP / 路径等"
    severity = Severity.HIGH
    supported_attack_params = []

    def __init__(self, http_client=None, config=None):
        super().__init__(http_client, config)

    async def detect(self, context: ScanContext) -> List[Finding]:
        """执行敏感信息检测."""
        findings: List[Finding] = []

        # 1) 扫描 HTML 注释
        seen: set = set()
        for comment in context.html_comments:
            if not comment or len(comment) < 10:
                continue
            result = self._scan_text(comment, "HTML 注释")
            for f in result:
                key = f"{f.name}:{f.evidence[:50]}"
                if key not in seen:
                    seen.add(key)
                    findings.append(f)

        # 2) 如果有 HTTP 客户端，扫描端点响应
        http = self.get_http_client()
        if http and context.endpoints:
            checked: set = set()
            for ep in context.endpoints[:20]:  # 限制最多 20 个端点
                url = ep.get("url", "")
                if not url or url in checked:
                    continue
                checked.add(url)

                try:
                    resp = await http.get(url)
                    body = resp.text
                    result = self._scan_text(body, url)
                    for f in result:
                        key = f"{f.name}:{f.evidence[:50]}"
                        if key not in seen:
                            seen.add(key)
                            findings.append(f)

                    # 检查响应头中的敏感信息
                    for header_key, header_value in resp.headers.items():
                        if header_key.lower() in ("server", "x-powered-by", "x-aspnet-version"):
                            findings.append(Finding(
                                name=f"响应头信息泄露: {header_key}",
                                description=f"响应头 {header_key} 暴露了服务器信息",
                                severity=Severity.LOW,
                                confidence=Confidence.CERTAIN,
                                url=url,
                                evidence=f"{header_key}: {header_value}",
                                remediation="移除或混淆 Server / X-Powered-By 等头信息",
                                cwe="CWE-200",
                            ))

                except Exception as e:
                    logger.debug("敏感信息扫描异常 %s: %s", url, e)

        return findings

    def _scan_text(self, text: str, source: str) -> List[Finding]:
        """扫描文本中的敏感模式."""
        findings = []

        for entry in SENSITIVE_PATTERNS:
            try:
                for match in entry["pattern"].finditer(text):
                    matched = match.group().strip()
                    # 过滤掉明显不是敏感信息的误报
                    if self._is_false_positive(matched):
                        continue

                    findings.append(Finding(
                        name=f"{entry['name']} 泄露",
                        description=entry["description"],
                        severity=entry["severity"],
                        confidence=Confidence.MEDIUM,
                        url=source,
                        evidence=matched[:150],
                        remediation="移除源代码中的敏感信息，使用环境变量或密钥管理服务",
                        cwe=entry["cwe"],
                        details={"pattern_name": entry["name"]},
                    ))
                    # 每个模式只报告一次同一来源
                    break
            except re.error:
                continue

        return findings

    def _is_false_positive(self, matched: str) -> bool:
        """过滤明显误报."""
        # 过滤常见的非敏感上下文
        false_indicators = [
            "example", "sample", "placeholder", "your_key", "your-secret",
            "your_api", "changeme", "test_key", "demo",
        ]
        lower = matched.lower()
        for indicator in false_indicators:
            if indicator in lower:
                return True
        # 过短的匹配可能是误报
        if len(matched) < 8:
            return True
        return False
