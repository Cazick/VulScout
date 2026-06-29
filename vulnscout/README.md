
<p align="center">
  <h1 align="center">VulnScout</h1>
  <p align="center">
    可扩展的 Web 漏洞扫描器 &middot; 插件化架构 &middot; 异步引擎
    <br/>
    <a href="#-功能特性">功能特性</a>
    &middot; <a href="#-快速开始">快速开始</a>
    &middot; <a href="#-使用示例">使用示例</a>
    &middot; <a href="#-项目架构">项目架构</a>
    &middot; <a href="#-开发指南">开发指南</a>
  </p>
</p>

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-22%20passed-brightgreen)

</div>

---

## 📖 项目简介

**VulnScout** 是一款基于 Python 的 Web 漏洞扫描器，采用**插件化架构**和**异步 I/O 引擎**。内置爬虫自动发现攻击面，支持多种常见漏洞类型的自动化检测，并提供终端、HTML、JSON 等多种报告输出方式。

> 🎯 适用于：安全测试人员、开发者在授权范围内进行 Web 安全评估。

---

## ✨ 功能特性

| 特性 | 说明 |
|------|------|
| 🧩 **插件化检测器** | 每种漏洞独立插件，通过注册表热插拔，新增检测器只需继承 `BaseDetector` |
| ⚡ **异步高并发** | 基于 `asyncio` + `httpx` 的异步引擎，高效处理大量请求 |
| 🔍 **智能爬虫** | 自动发现 URL 端点、表单入口、JavaScript 文件、HTML 注释 |
| 📊 **多格式报告** | 支持终端 Rich 表格、HTML 页面、JSON 三种输出格式 |
| 🌐 **Web 管理界面** | FastAPI + Tailwind CSS 构建的可视化仪表盘，支持在线启动扫描 |
| 🐳 **Docker 部署** | 一键启动，开箱即用 |

### 支持的检测器

| 检测器 | 类型 | 级别 |
|--------|------|------|
| **XSS 检测** | 反射型跨站脚本 (多上下文感知) | 🔴 High |
| **SQL 注入检测** | 报错注入 / 布尔盲注 / 时间盲注 | 🔴 Critical |
| **安全响应头检测** | CSP / HSTS / XFO / CORS 等 9 项检查 | 🟡 Medium |
| **敏感信息泄露检测** | API Key / 密码 / 内网 IP / 数据库连接串等 | 🔴 Critical |

---

## 🚀 快速开始

### 前提条件

- Python 3.10+
- pip

### 安装

```bash
# 克隆仓库
git clone https://github.com/Cazick/VulScout.git
cd VulScout

# 安装依赖
pip install .

# 验证安装
vulnscout --version
```

### 可选依赖

```bash
# Web UI 界面
pip install ".[web]"

# 开发测试
pip install ".[dev]"
```

---

## 💻 使用示例

### 1️⃣ 终端扫描

```bash
# 快速扫描（仅检查安全响应头）
vulnscout scan https://example.com --only-headers

# 完整扫描（指定检测器）
vulnscout scan https://example.com -D xss,sqli,headers,sensitive_data

# 带爬虫的深度扫描
vulnscout scan https://example.com --depth 3 --max-pages 50

# 生成 HTML 报告
vulnscout scan https://example.com --format html --output report.html

# 生成 JSON 报告
vulnscout scan https://example.com -D headers --format json --output report.json

# 通过代理扫描（配合 Burp Suite 抓包调试）
vulnscout scan https://example.com --proxy http://127.0.0.1:8080

# 详细日志输出
vulnscout scan https://example.com -v
```

### 2️⃣ 启动 Web UI

```bash
vulnscout web

# 指定端口
vulnscout web --port 8080
```

浏览器打开 `http://127.0.0.1:8080`，输入目标 URL 即可在线启动扫描。

### 3️⃣ 生成配置文件

```bash
vulnscout init
```

生成 `vulnscout_config.yaml` 文件，可自定义扫描参数。

---

## 🏗️ 项目架构

```
VulScout/
├── vulnscout/
│   ├── main.py                # CLI 入口 (Click)
│   ├── config.py              # 配置管理 (dataclass + YAML)
│   │
│   ├── core/                  # 核心引擎
│   │   ├── crawler.py         # 异步爬虫 — URL 发现、表单提取
│   │   ├── engine.py          # 扫描引擎 — 统筹爬虫→检测器→报告
│   │   ├── http_client.py     # HTTP 客户端 (httpx 封装)
│   │   └── exceptions.py      # 自定义异常
│   │
│   ├── detectors/             # 漏洞检测器 (插件系统)
│   │   ├── base.py            # 插件基类 + Finding 数据模型
│   │   ├── xss.py             # XSS 检测器
│   │   ├── sqli.py            # SQL 注入检测器
│   │   ├── security_headers.py# 安全响应头检测器
│   │   ├── sensitive_data.py  # 敏感信息泄露检测器
│   │   └── payloads/          # 检测 Payload 库
│   │
│   ├── reporter/              # 报告生成
│   │   ├── html_reporter.py   # HTML 报告
│   │   └── json_reporter.py   # JSON 报告
│   │
│   └── ui/                    # Web 界面
│       ├── server.py          # FastAPI 服务
│       └── templates/         # 前端模板
│
├── tests/                     # 单元测试
│   ├── test_crawler.py
│   └── test_detectors.py
│
├── Dockerfile                 # Docker 构建
├── docker-compose.yml         # Docker Compose
└── pyproject.toml             # 项目配置
```

### 扫描流程

```
目标 URL
    │
    ▼
┌─────────────┐
│   Crawler   │ ──→ 发现 URL、表单、JS、注释
└──────┬──────┘
       ▼
┌─────────────┐
│   Engine    │ ──→ 加载检测器插件，并发调度
└──────┬──────┘
       ▼
┌─────────────┐
│  Detectors  │ ──→ XSS → SQLi → Headers → SensitiveData
└──────┬──────┘
       ▼
┌─────────────┐
│  Reporter   │ ──→ Terminal / HTML / JSON
└─────────────┘
```

---

## 🔧 开发指南

### 添加一个新的检测器

插件系统设计为可扩展的，添加新检测器只需 3 步：

```python
# 1. 在 vulnscout/detectors/ 下创建新文件
# 2. 继承 BaseDetector 并实现 detect() 方法
from vulnscout.detectors import BaseDetector, Finding, ScanContext, Severity

class MyDetector(BaseDetector):
    name = "my_detector"
    description = "我的自定义检测器"
    severity = Severity.MEDIUM

    async def detect(self, context: ScanContext) -> list[Finding]:
        # 实现你的检测逻辑
        findings = []
        # ...
        return findings

# 3. 在 __init__.py 中注册：register_detector(MyDetector)
```

### 运行测试

```bash
# 安装开发依赖
pip install ".[dev]"

# 运行全部测试
pytest

# 带覆盖率报告
pytest --cov=vulnscout tests/
```

### Docker 部署

```bash
# 构建镜像
docker build -t vulnscout .

# 运行
docker run -p 8080:8080 vulnscout

# 或使用 docker-compose
docker-compose up -d
```

---

## 🧪 测试

| 模块 | 测试数 | 说明 |
|------|--------|------|
| Crawler | 10 | URL 规范化、链接提取、表单提取、注释提取 |
| Detector Registry | 3 | 插件注册、列表、属性验证 |
| Security Headers | 2 | 缺失头检测、CSP 配置检查 |
| Sensitive Data | 2 | API Key 检测、AWS 密钥检测 |
| Data Model | 2 | Finding 初始化、严重等级排序 |

**总计: 22/22 测试通过**

---

## 📄 License

[MIT](LICENSE)

---

> **⚠️ 免责声明：** 本工具仅用于授权的安全测试和教育目的。未经授权扫描他人网站可能违反当地法律法规。使用者需自行承担法律责任。
