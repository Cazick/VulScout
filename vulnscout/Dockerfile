# VulnScout Dockerfile
FROM python:3.12-slim

LABEL description="VulnScout -- Web Vulnerability Scanner"
LABEL version="0.1.0"

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制项目
COPY pyproject.toml README.md ./
COPY vulnscout/ ./vulnscout/

# 安装 Python 依赖
RUN pip install --no-cache-dir -e ".[web]"

# 创建非 root 用户
RUN useradd -m -s /bin/bash vulnscout && chown -R vulnscout:vulnscout /app
USER vulnscout

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

# 默认启动 Web UI
EXPOSE 8080
ENTRYPOINT ["vulnscout"]
CMD ["web", "--host", "0.0.0.0", "--port", "8080"]
