"""Detector 插件基类 -- 所有漏洞检测器继承此基类."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, ClassVar, Dict, List, Optional


class Severity(Enum):
    """漏洞严重级别."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other):
        if not isinstance(other, Severity):
            return NotImplemented
        order = ["critical", "high", "medium", "low", "info"]
        return order.index(self.value) < order.index(other.value)

    def __str__(self) -> str:
        return self.value


class Confidence(Enum):
    """检测置信度."""
    CERTAIN = "certain"       # 100% 确认
    HIGH = "high"             # 高度可疑
    MEDIUM = "medium"         # 可能
    LOW = "low"               # 猜测

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """单个漏洞发现."""

    name: str                              # 漏洞名称 (如 "反射型 XSS")
    description: str                       # 详细描述
    severity: Severity                     # 严重等级
    confidence: Confidence = Confidence.MEDIUM  # 置信度
    url: str = ""                          # 漏洞出现 URL
    parameter: str = ""                    # 涉及的参数名
    payload: str = ""                      # 触发的 Payload
    evidence: str = ""                     # 证据（响应片段）
    remediation: str = ""                  # 修复建议
    cwe: str = ""                          # CWE 编号
    details: Dict[str, Any] = field(default_factory=dict)  # 额外信息


@dataclass
class ScanContext:
    """传给检测器的扫描上下文."""

    target_url: str = ""
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    html_comments: List[str] = field(default_factory=list)
    raw_responses: Dict[str, str] = field(default_factory=dict)


class BaseDetector(ABC):
    """所有漏洞检测器的基类.

    子类只需实现 detect() 方法，框架自动完成插件注册和调度.
    """

    # ---- 子类必须覆写的属性 ----
    name: ClassVar[str] = ""               # 检测器名称 (如 "xss")
    description: ClassVar[str] = ""        # 描述
    severity: ClassVar[Severity] = Severity.MEDIUM
    supported_attack_params: ClassVar[List[str]] = ["query", "form", "headers"]

    def __init__(self, http_client=None, config=None):
        self._http = http_client
        self._config = config or {}

    @abstractmethod
    async def detect(self, context: ScanContext) -> List[Finding]:
        """执行检测，返回发现的漏洞列表.

        子类必须实现此方法.
        """
        ...

    def get_http_client(self):
        """获取 HTTP 客户端."""
        return self._http

    def get_config(self, key: str, default=None):
        """获取检测器配置."""
        return self._config.get(key, default)

    def __str__(self) -> str:
        return f"{self.name} ({self.description})"
