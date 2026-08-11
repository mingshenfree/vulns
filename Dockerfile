# Strix Enhanced - Dockerfile
# 基于 Kali Linux，集成 Burp/终端截图生成及 XLSX 合规报告功能
# 优化了中国大陆镜像源加速

FROM kalilinux/kali-rolling:latest

# 设置环境变量
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# 1. 替换为清华大学镜像源 (解决 Ign 超时问题)
RUN sed -i 's|http://kali.download/kali|https://mirrors.tuna.tsinghua.edu.cn/kali|g' /etc/apt/sources.list && \
    sed -i 's|http://mirrors.ocf.berkeley.edu/kali|https://mirrors.tuna.tsinghua.edu.cn/kali|g' /etc/apt/sources.list && \
    sed -i 's|http://kali.darklab.sh/kali|https://mirrors.tuna.tsinghua.edu.cn/kali|g' /etc/apt/sources.list

# 2. 安装系统依赖
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    git \
    curl \
    wget \
    xvfb \
    xauth \
    x11-utils \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    # 安全工具
    nuclei \
    sqlmap \
    whatweb \
    dirb \
    gobuster \
    # 清理
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# 3. 安装 Playwright 浏览器依赖
RUN pip3 install playwright && \
    playwright install chromium && \
    playwright install-deps chromium

# 4. 设置工作目录
WORKDIR /app/strix

# 5. 复制项目文件
COPY . .

# 6. 安装 Python 依赖
RUN pip3 install -e . && \
    pip3 install openpyxl python-docx streamlit fastapi uvicorn python-multipart

# 7. 创建挂载点目录
RUN mkdir -p /app/workspace /app/test_cases /app/reports /app/screenshots

# 8. 设置入口点
ENTRYPOINT ["/bin/bash", "-c"]
