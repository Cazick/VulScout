"""检测器单元测试."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from vulnscout.detectors.base import Finding, ScanContext, Severity, Confidence
from vulnscout.detectors.security_headers import SecurityHeadersDetector
from vulnscout.detectors.sensitive_data import SensitiveDataDetector
from vulnscout.detectors import get_all_detectors, list_available_detectors


class TestDetectorRegistry:
    """测试检测器注册."""

    def test_all_detectors_registered(self):
        """所有检测器都已注册."""
        all_dets = get_all_detectors()
        assert "xss" in all_dets
        assert "sqli" in all_dets
        assert "headers" in all_dets
        assert "sensitive_data" in all_dets

    def test_list_detectors(self):
        """列出检测器."""
        names = list_available_detectors()
        assert "xss" in names
        assert "sqli" in names

    def test_detector_attributes(self):
        """检测器属性完整."""
        all_dets = get_all_detectors()
        for name, cls in all_dets.items():
            assert cls.name, f"{name} 缺少 name"
            assert cls.description, f"{name} 缺少 description"


class TestSecurityHeadersDetector:
    """Test security headers detector."""

    @pytest.mark.asyncio
    async def test_detect_missing_headers(self):
        """检测缺失的安全头."""
        http = AsyncMock()

        # Mock response with no security headers
        mock_resp = MagicMock()
        mock_resp.headers = {
            "content-type": "text/html",
            "date": "Mon, 01 Jan 2024 00:00:00 GMT",
        }
        http.get.return_value = mock_resp

        detector = SecurityHeadersDetector(http_client=http)
        context = ScanContext(
            target_url="https://example.com/",
            endpoints=[{"url": "https://example.com/", "method": "GET"}],
        )
        findings = await detector.detect(context)
        assert len(findings) >= 7  # 至少检测到 7 个缺失的安全头

    @pytest.mark.asyncio
    async def test_detect_with_csp(self):
        """检测 CSP 配置问题."""
        http = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.headers = {
            "content-type": "text/html",
            "content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
        }
        http.get.return_value = mock_resp

        detector = SecurityHeadersDetector(http_client=http)
        context = ScanContext(
            target_url="https://example.com/",
            endpoints=[{"url": "https://example.com/", "method": "GET"}],
        )
        findings = await detector.detect(context)
        csp_findings = [f for f in findings if "CSP" in f.name]
        assert len(csp_findings) >= 2  # unsafe-inline + unsafe-eval


class TestSensitiveDataDetector:
    """Test sensitive data detector."""

    @pytest.mark.asyncio
    async def test_detect_api_key_in_comment(self):
        """检测注释中的 API key."""
        detector = SensitiveDataDetector()
        context = ScanContext(
            target_url="https://example.com/",
            html_comments=[
                "TODO: integrate with API key=sk_live_1234567890abcdef",
                "Normal comment without secrets",
            ],
        )
        findings = await detector.detect(context)
        api_key_findings = [f for f in findings if "API" in f.name]
        assert len(api_key_findings) >= 1

    @pytest.mark.asyncio
    async def test_detect_aws_key(self):
        """检测 AWS 密钥."""
        detector = SensitiveDataDetector()
        # Must not contain false-positive indicators like 'example'
        comment_text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYTESTKEY123"
        context = ScanContext(
            target_url="https://example.com/",
            html_comments=[comment_text],
        )
        findings = await detector.detect(context)
        aws_findings = [f for f in findings if "AWS" in f.name]
        assert len(aws_findings) >= 1


class TestFindingModel:
    """测试 Finding 数据模型."""

    def test_finding_creation(self):
        """完全初始化 Finding."""
        f = Finding(
            name="Test XSS",
            description="A test finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            url="https://example.com/page?q=test",
            parameter="q",
            payload="<script>alert(1)</script>",
            evidence="<script>alert(1)</script>",
            remediation="Sanitize input",
            cwe="CWE-79",
        )
        assert f.name == "Test XSS"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.HIGH

    def test_severity_order(self):
        """严重等级排序."""
        levels = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for i in range(len(levels) - 1):
            assert levels[i] < levels[i + 1], f"{levels[i]} should be < {levels[i+1]}"
