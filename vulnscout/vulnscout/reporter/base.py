"""报告生成器基类."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List

from vulnscout.detectors.base import Finding


@dataclass
class Report:
    """报告数据."""

    target_url: str
    findings: List[Finding] = field(default_factory=list)
    scan_summary: dict = field(default_factory=dict)
    scan_duration: float = 0.0

    @property
    def total(self) -> int:
        return len(self.findings)

    @property
    def by_severity(self) -> dict:
        result: dict = {}
        for f in self.findings:
            key = f.severity.value
            result[key] = result.get(key, 0) + 1
        return result


class BaseReporter(ABC):
    """报告生成器基类."""

    @abstractmethod
    def generate(self, report: Report, output_path: str = "") -> str:
        """生成报告，返回报告内容或文件路径."""
        ...
