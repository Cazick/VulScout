# VulnScout 🕵️

> 可扩展的 Web 漏洞扫描器 -- 插件化架构，异步引擎，开箱即用。

## 功能

- 🔍 **智能爬虫** -- 自动发现 URL、表单、API 端点
- 🧩 **插件化检测器** -- 每种漏洞独立插件，热插拔
- ⚡ **异步并发** -- 基于 httpx + asyncio 的高并发扫描
- 📊 **多格式报告** -- HTML / JSON / 终端 Rich 输出
- 🎯 **精准检测** -- 误报过滤，多种 Payload 策略
- 🐳 **Docker 部署** -- 一键启动

## 快速开始

```bash
# 安装
pip install vulnscout

# 扫描一个网站
vulnscout scan https://example.com

# 指定检测器 + 输出报告
vulnscout scan https://example.com \
    --detectors xss,sqli,headers \
    --output report.html

# 启动 Web UI
vulnscout web
```

## 支持的检测器

| 检测器 | 类型 | 状态 |
|--------|------|------|
| XSS Detector | 反射型/存储型/上下文感知 | ✅ |
| SQLi Detector | 报错注入/盲注/时间盲注 | ✅ |
| Security Headers | CSP/HSTS/XFO/CT 等 | ✅ |
| Sensitive Data | 密钥/路径/注释泄露 | ✅ |
| Directory Traversal | 路径遍历 | ✅ |
| CSRF Detector | 表单 Token 检测 | ✅ |
| SSRF Detector | 服务端请求伪造 | ⏳ |

## 架构

```
vulnscout/
├── core/           # 引擎 + 爬虫 + HTTP 客户端
├── detectors/      # 漏洞检测器插件
│   ├── base.py     # 插件基类
│   ├── xss.py      # XSS 检测
│   ├── sqli.py     # SQL 注入检测
│   └── ...
├── reporter/       # 报告生成器
└── main.py         # CLI 入口
```

## 开发

```bash
git clone https://github.com/yourname/vulnscout
cd vulnscout
pip install -e ".[dev]"
pytest
```

## License

MIT
