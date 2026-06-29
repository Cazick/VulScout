"""Security Headers Detector -- 检查 HTTP 安全响应头配置."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from vulnscout.detectors.base import (
    BaseDetector,
    Confidence,
    Finding,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)

# 需要检查的安全头及其说明
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": Severity.HIGH,
        "description": "缺少 CSP 头，可能导致 XSS 和数据注入攻击",
        "remediation": "添加 Content-Security-Policy 头，限制可加载的资源来源",
        "cwe": "CWE-1021",
    },
    "Strict-Transport-Security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": Severity.MEDIUM,
        "description": "缺少 HSTS 头，无法强制 HTTPS 连接",
        "remediation": "添加 Strict-Transport-Security 头，建议 max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "X-Content-Type-Options": {
        "name": "X-Content-Type-Options",
        "severity": Severity.MEDIUM,
        "description": "缺少 X-Content-Type-Options: nosniff 头，可能导致 MIME 类型混淆攻击",
        "remediation": "添加 X-Content-Type-Options: nosniff 头",
        "cwe": "CWE-345",
    },
    "X-Frame-Options": {
        "name": "X-Frame-Options",
        "severity": Severity.MEDIUM,
        "description": "缺少 X-Frame-Options 头，可能存在点击劫持风险",
        "remediation": "添加 X-Frame-Options: DENY 或 SAMEORIGIN 头",
        "cwe": "CWE-1021",
    },
    "X-XSS-Protection": {
        "name": "X-XSS-Protection",
        "severity": Severity.LOW,
        "description": "缺少 X-XSS-Protection 头",
        "remediation": "添加 X-XSS-Protection: 1; mode=block 头",
        "cwe": "CWE-79",
    },
    "Referrer-Policy": {
        "name": "Referrer-Policy",
        "severity": Severity.LOW,
        "description": "缺少 Referrer-Policy 头，可能泄露 URL 中的敏感信息",
        "remediation": "添加 Referrer-Policy: no-referrer 或 strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "name": "Permissions-Policy",
        "severity": Severity.LOW,
        "description": "缺少 Permissions-Policy 头，未限制浏览器 API 权限",
        "remediation": "添加 Permissions-Policy 头，限制不需要的浏览器功能",
        "cwe": "CWE-693",
    },
    "Cache-Control": {
        "name": "Cache-Control (敏感信息缓存)",
        "severity": Severity.LOW,
        "description": "响应缺少 Cache-Control: no-store 头，敏感信息可能被缓存",
        "remediation": "对包含敏感信息的响应添加 Cache-Control: no-store",
        "cwe": "CWE-525",
    },
    "Access-Control-Allow-Origin": {
        "name": "CORS 配置",
        "severity": Severity.MEDIUM,
        "description": "CORS 配置过于宽松，允许任意来源访问",
        "remediation": "限制 Access-Control-Allow-Origin 为特定可信域名",
        "cwe": "CWE-942",
    },
}

# CSP 检查清单
CSP_CHECKS = [
    {
        "check": lambda csp: "default-src" not in csp and "script-src" not in csp,
        "finding": "CSP 未设置 script-src 或 default-src",
        "severity": Severity.HIGH,
    },
    {
        "check": lambda csp: "'unsafe-inline'" in csp,
        "finding": "CSP 允许 unsafe-inline，降低了 XSS 防护效果",
        "severity": Severity.MEDIUM,
    },
    {
        "check": lambda csp: "'unsafe-eval'" in csp,
        "finding": "CSP 允许 unsafe-eval，存在 eval() 注入风险",
        "severity": Severity.MEDIUM,
    },
    {
        "check": lambda csp: "https:" in csp and "http:" in csp,
        "finding": "CSP 允许 HTTP 资源加载，建议仅允许 HTTPS",
        "severity": Severity.LOW,
    },
]


class SecurityHeadersDetector(BaseDetector):
    """HTTP 安全响应头检测器.

    检查目标网站的响应头中是否包含关键安全头，并评估 CSP 配置质量.
    这是一个绿色检测（只读取响应头，不发送恶意请求）.
    """

    name = "headers"
    description = "HTTP 安全响应头配置检查"
    severity = Severity.MEDIUM
    supported_attack_params = []

    async def detect(self, context: ScanContext) -> List[Finding]:
        """执行安全头检测."""
        findings: List[Finding] = []
        http = self.get_http_client()
        if not http:
            return findings

        if not context.endpoints:
            # 如果没有爬取结果，至少检查目标 URL
            urls_to_check = [context.target_url] if context.target_url else []
        else:
            urls_to_check = [ep.get("url", "") for ep in context.endpoints if ep.get("url")]

        # 去重并限制最多检查 10 个页面
        checked: set = set()
        for url in urls_to_check:
            if url in checked or len(checked) >= 10:
                continue
            checked.add(url)

            try:
                resp = await http.get(url)
                headers = resp.headers

                # 检查每个安全头是否存在
                for header_key, info in SECURITY_HEADERS.items():
                    value = headers.get(header_key.lower(), "")
                    if not value:
                        # 头不存在
                        finding = Finding(
                            name=info["name"],
                            description=info["description"],
                            severity=info["severity"],
                            confidence=Confidence.CERTAIN,
                            url=url,
                            remediation=info["remediation"],
                            cwe=info["cwe"],
                            details={"header": header_key, "status": "missing"},
                        )
                        findings.append(finding)
                    else:
                        # 头存在但可能配置不当
                        sub_findings = self._check_header_quality(header_key, value, url)
                        findings.extend(sub_findings)

                # 特别检查 CORS
                cors_origin = headers.get("access-control-allow-origin", "")
                if cors_origin == "*":
                    findings.append(Finding(
                        name="CORS 配置过于宽松",
                        description="Access-Control-Allow-Origin: * 允许任意跨域请求",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CERTAIN,
                        url=url,
                        evidence=cors_origin,
                        remediation="将 Access-Control-Allow-Origin 设为特定域名而非 *",
                        cwe="CWE-942",
                    ))

            except Exception as e:
                logger.debug("安全头检测异常 %s: %s", url, e)

        return findings

    def _check_header_quality(self, header_key: str, value: str, url: str) -> List[Finding]:
        """检查已存在的安全头配置质量."""
        findings = []

        if header_key == "Content-Security-Policy":
            for check in CSP_CHECKS:
                if check["check"](value):
                    findings.append(Finding(
                        name=f"CSP 配置问题: {check['finding']}",
                        description=f"CSP 头存在但配置不完善: {check['finding']}",
                        severity=check["severity"],
                        confidence=Confidence.HIGH,
                        url=url,
                        evidence=value[:200],
                        remediation="根据 OWASP CSP Cheat Sheet 优化 CSP 策略",
                        cwe="CWE-1021",
                    ))

        elif header_key == "Strict-Transport-Security":
            if "max-age=0" in value:
                findings.append(Finding(
                    name="HSTS max-age=0",
                    description="HSTS max-age=0 禁用了 HSTS",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    evidence=value,
                    remediation="设置 max-age 为至少 31536000 (1年)",
                    cwe="CWE-319",
                ))
            elif not any(c.isdigit() for c in value):
                findings.append(Finding(
                    name="HSTS 缺少 max-age",
                    description="HSTS 头未设置 max-age",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    evidence=value,
                    remediation="添加 max-age=31536000; includeSubDomains",
                    cwe="CWE-319",
                ))

        elif header_key == "X-Frame-Options":
            if value.upper() not in ("DENY", "SAMEORIGIN"):
                findings.append(Finding(
                    name="X-Frame-Options 配置不当",
                    description=f"X-Frame-Options 值 '{value}' 不是推荐的 DENY 或 SAMEORIGIN",
                    severity=Severity.LOW,
                    confidence=Confidence.CERTAIN,
                    url=url,
                    evidence=value,
                    remediation="使用 X-Frame-Options: DENY 或 SAMEORIGIN",
                    cwe="CWE-1021",
                ))

        return findings
