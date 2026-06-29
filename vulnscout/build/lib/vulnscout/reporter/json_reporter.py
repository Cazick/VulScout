"""JSON 报告生成器 -- 机器可读的扫描报告."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List

from vulnscout.detectors.base import Finding
from vulnscout.reporter.base import BaseReporter, Report


class JSONReporter(BaseReporter):
    """JSON 格式报告生成器."""

    def generate(self, report: Report, output_path: str = "") -> str:
        """生成 JSON 报告."""
        data = self._build_json(report)
        json_str = json.dumps(data, ensure_ascii=False, indent=2, default=str)

        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json_str)
            return output_path
        return json_str

    def _build_json(self, report: Report) -> Dict[str, Any]:
        """构建 JSON 数据结构."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            report.findings,
            key=lambda f: severity_order.get(f.severity.value, 99),
        )

        return {
            "tool": {
                "name": "VulnScout",
                "version": "0.1.0",
            },
            "scan": {
                "target_url": report.target_url,
                "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "duration_seconds": round(report.scan_duration, 2),
                "summary": report.scan_summary,
            },
            "findings": [self._finding_to_dict(f) for f in sorted_findings],
            "statistics": {
                "total": len(report.findings),
                "by_severity": report.by_severity,
            },
        }

    def _finding_to_dict(self, f: Finding) -> Dict[str, Any]:
        """将 Finding 对象转为字典."""
        result: Dict[str, Any] = {
            "name": f.name,
            "description": f.description,
            "severity": f.severity.value,
            "confidence": f.confidence.value,
            "url": f.url,
            "parameter": f.parameter,
            "payload": f.payload,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "cwe": f.cwe,
        }
        if f.details:
            result["details"] = f.details
        return result
