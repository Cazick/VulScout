"""XSS (Cross-Site Scripting) Detector -- 反射型 / 存储型 / 上下文感知."""

from __future__ import annotations

import logging
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

# XSS 检测 Payload 集
XSS_PAYLOADS: List[Dict] = [
    # 基础 script 标签
    {"payload": "<script>alert(1)</script>", "context": "html", "description": "基础 script 标签注入"},
    {"payload": "<script>confirm(document.domain)</script>", "context": "html", "description": "script 标签调用 confirm"},

    # 事件处理器
    {"payload": "<img src=x onerror=alert(1)>", "context": "html", "description": "img onerror 事件"},
    {"payload": "<svg onload=alert(1)>", "context": "html", "description": "svg onload 事件"},
    {"payload": "<body onload=alert(1)>", "context": "html", "description": "body onload 事件"},
    {"payload": "<input autofocus onfocus=alert(1)>", "context": "html", "description": "input onfocus 事件"},
    {"payload": "<details open ontoggle=alert(1)>", "context": "html", "description": "details ontoggle 事件"},
    {"payload": "<select autofocus onfocus=alert(1)>", "context": "html", "description": "select onfocus 事件"},
    {"payload": "<textarea autofocus onfocus=alert(1)>", "context": "html", "description": "textarea onfocus 事件"},

    # JS 上下文逃逸
    {"payload": "'-alert(1)-'", "context": "js", "description": "单引号 JS 上下文逃逸"},
    {"payload": "';alert(1)//", "context": "js", "description": "单引号闭合 + alert"},
    {"payload": "\";alert(1)//", "context": "js", "description": "双引号闭合 + alert"},
    {"payload": "</script><script>alert(1)</script>", "context": "html", "description": "script 标签闭合注入"},

    # 属性上下文逃逸
    {"payload": "\" onmouseover=alert(1) \"", "context": "attr", "description": "属性双引号逃逸 + 事件"},
    {"payload": "' onmouseover=alert(1) '", "context": "attr", "description": "属性单引号逃逸 + 事件"},
    {"payload": "\" onfocus=alert(1) autofocus=\"", "context": "attr", "description": "属性逃逸 + autofocus"},

    # Polyglot / 组合
    {"payload": "\"'--><script>alert(1)</script>", "context": "html", "description": "多上下文组合注入"},
]

# XSS 检测关键词 -- 响应中包含这些字符串表示 payload 可能被执行
XSS_SUCCESS_INDICATORS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "alert(1)",
]

# HTML 上下文敏感字符
HTML_SPECIAL_CHARS = {"<", ">", "\"", "'", "&"}


class XSSDetector(BaseDetector):
    """跨站脚本 (XSS) 漏洞检测器.

    检测反射型 XSS：将 Payload 注入 URL 参数、表单字段中，
    检查响应是否未正确转义地返回了 Payload.
    """

    name = "xss"
    description = "跨站脚本攻击 (XSS) 检测 -- 反射型"
    severity = Severity.HIGH
    supported_attack_params = ["query", "form"]

    def __init__(self, http_client=None, config=None):
        super().__init__(http_client, config)
        self._payloads = XSS_PAYLOADS

    async def detect(self, context: ScanContext) -> List[Finding]:
        """执行 XSS 检测."""
        findings: List[Finding] = []
        http = self.get_http_client()
        if not http:
            logger.warning("XSSDetector: 无 HTTP 客户端，跳过")
            return findings

        # 1) 检测 URL 查询参数中的反射 XSS
        for ep in context.endpoints:
            url = ep.get("url", "")
            if not url or ep.get("method", "GET") != "GET":
                continue

            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if not params:
                continue

            # 对每个参数测试 Payload
            for param_name, param_values in params.items():
                if not param_values or not param_values[0]:
                    continue

                for p_entry in self._payloads:
                    payload = p_entry["payload"]
                    test_url = self._inject_param(url, param_name, payload)

                    try:
                        resp = await http.get(test_url)
                        body = resp.text

                        if self._payload_reflected(body, payload, param_name):
                            # 确认是否真的未转义
                            severity = self._assess_severity(body, payload)
                            finding = Finding(
                                name=f"反射型 XSS ({p_entry['context']} 上下文)",
                                description=p_entry["description"],
                                severity=severity,
                                confidence=Confidence.HIGH,
                                url=test_url,
                                parameter=param_name,
                                payload=payload,
                                evidence=self._extract_evidence(body, payload),
                                remediation=self._get_remediation(p_entry["context"]),
                                cwe="CWE-79",
                                details={
                                    "context": p_entry["context"],
                                    "original_url": url,
                                },
                            )
                            findings.append(finding)
                            break  # 一个参数有一个命中就够了
                    except Exception as e:
                        logger.debug("XSS 检测请求异常 %s: %s", test_url, e)

        # 2) 检测表单字段
        for form in context.forms:
            action = form.get("action_url", "")
            if not action:
                continue
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            if not inputs:
                continue

            for inp in inputs:
                inp_name = inp.get("name", "")
                if not inp_name:
                    continue
                inp_type = inp.get("type", "text")
                if inp_type in ("submit", "hidden", "image", "button"):
                    continue

                for p_entry in self._payloads:
                    payload = p_entry["payload"]
                    form_data = self._build_form_data(inputs, inp_name, payload)

                    try:
                        if method == "POST":
                            resp = await http.post(action, data=form_data)
                        else:
                            resp = await http.get(action, params=form_data)
                        body = resp.text

                        if self._payload_reflected(body, payload, inp_name):
                            finding = Finding(
                                name=f"表单反射型 XSS ({p_entry['context']} 上下文)",
                                description=f"表单字段 '{inp_name}' 中的 {p_entry['description']}",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                url=action,
                                parameter=inp_name,
                                payload=payload,
                                evidence=self._extract_evidence(body, payload),
                                remediation=self._get_remediation(p_entry["context"]),
                                cwe="CWE-79",
                            )
                            findings.append(finding)
                            break
                    except Exception as e:
                        logger.debug("XSS 表单检测异常 %s: %s", action, e)

        return findings

    def _inject_param(self, url: str, param_name: str, payload: str) -> str:
        """将 Payload 注入到 URL 的指定参数中."""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        params[param_name] = [payload]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    def _payload_reflected(self, body: str, payload: str, param_name: str) -> bool:
        """检测 Payload 是否在响应中被反射."""
        if payload not in body:
            return False
        # 检查是否被 HTML 实体编码 (转了义就不算漏洞)
        import html as html_mod
        escaped = html_mod.escape(payload)
        if escaped in body and payload not in body.replace(escaped, ""):
            # 只有转义版本没有原始版本 → 安全
            # 但如果有原始版本也在响应中，仍有风险
            pass
        # 检查 payload 中的关键字符是否被编码
        for ch in HTML_SPECIAL_CHARS:
            encoded = urllib.parse.quote(ch)
            if ch in payload and encoded in body and ch not in body:
                # 关键字符被 URL 编码了，但在响应中没出现原始字符 → 可能安全
                # 但继续检查 -- 可能其他地方出现了
                pass
        return True

    def _assess_severity(self, body: str, payload: str) -> Severity:
        """根据响应判断漏洞严重程度."""
        for indicator in XSS_SUCCESS_INDICATORS:
            if indicator in body:
                return Severity.CRITICAL
        if payload in body and any(ch in body for ch in ("<", ">", "\"")):
            return Severity.HIGH
        return Severity.MEDIUM

    def _extract_evidence(self, body: str, payload: str, context_chars: int = 100) -> str:
        """从响应 body 中提取 Payload 附近的片段作为证据."""
        idx = body.find(payload)
        if idx == -1:
            return payload[:200]
        start = max(0, idx - context_chars)
        end = min(len(body), idx + len(payload) + context_chars)
        snippet = body[start:end]
        # 高亮 payload
        return snippet

    def _build_form_data(
        self, inputs: List[Dict], target_name: str, payload: str
    ) -> Dict[str, str]:
        """构建表单数据，将指定字段设为 payload."""
        data = {}
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue
            if name == target_name:
                data[name] = payload
            else:
                # 使用默认值或空值
                data[name] = inp.get("value", "test")
        return data

    def _get_remediation(self, context: str) -> str:
        """根据上下文返回修复建议."""
        remediations = {
            "html": "对用户输入进行 HTML 实体编码，使用 OWASP XSS Filter Evasion Cheat Sheet 推荐的编码方式",
            "attr": "对属性值使用引号包裹并转义特殊字符，避免将用户输入直接拼接到事件处理器中",
            "js": "避免将用户输入拼接到 JavaScript 代码中，使用 textContent 而非 innerHTML",
        }
        return remediations.get(context, "对所有用户输入进行输出编码，实施 Content-Security-Policy")
