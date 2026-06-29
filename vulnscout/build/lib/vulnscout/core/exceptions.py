"""VulnScout 自定义异常."""


class VulnScoutException(Exception):
    """所有 VulnScout 异常的基类."""


class RequestError(VulnScoutException):
    """HTTP 请求相关错误."""


class CrawlerError(VulnScoutException):
    """爬虫相关错误."""


class DetectorError(VulnScoutException):
    """检测器相关错误."""


class ScanAbortedError(VulnScoutException):
    """扫描被用户中止."""


class ConfigError(VulnScoutException):
    """配置错误."""
