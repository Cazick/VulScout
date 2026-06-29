"""Detectors 包 -- 插件化漏洞检测器."""
from __future__ import annotations

from typing import Dict, List, Optional, Type

from vulnscout.detectors.base import (
    BaseDetector,
    Confidence,
    Finding,
    ScanContext,
    Severity,
)

# 检测器注册表 -- 通过 name 查找检测器类
_DETECTOR_REGISTRY: Dict[str, Type[BaseDetector]] = {}


def register_detector(detector_class: Type[BaseDetector]):
    """注册检测器到全局注册表."""
    name = detector_class.name
    if not name:
        raise ValueError(f"检测器类 {detector_class.__name__} 未设置 name 属性")
    _DETECTOR_REGISTRY[name] = detector_class


def get_detector(name: str) -> Optional[Type[BaseDetector]]:
    """按名称获取检测器类."""
    return _DETECTOR_REGISTRY.get(name)


def get_all_detectors() -> Dict[str, Type[BaseDetector]]:
    """获取所有已注册的检测器."""
    return dict(_DETECTOR_REGISTRY)


def list_available_detectors() -> List[str]:
    """列出所有已注册的检测器名称."""
    return sorted(_DETECTOR_REGISTRY.keys())


# 自动注册所有检测器
def _auto_register():
    try:
        from vulnscout.detectors.xss import XSSDetector
        register_detector(XSSDetector)
    except ImportError:
        pass
    try:
        from vulnscout.detectors.sqli import SQLiDetector
        register_detector(SQLiDetector)
    except ImportError:
        pass
    try:
        from vulnscout.detectors.security_headers import SecurityHeadersDetector
        register_detector(SecurityHeadersDetector)
    except ImportError:
        pass
    try:
        from vulnscout.detectors.sensitive_data import SensitiveDataDetector
        register_detector(SensitiveDataDetector)
    except ImportError:
        pass


_auto_register()


__all__ = [
    "BaseDetector",
    "Finding",
    "ScanContext",
    "Severity",
    "Confidence",
    "register_detector",
    "get_detector",
    "get_all_detectors",
    "list_available_detectors",
]
