# Strix 部署指南

## 环境要求

- Python 3.12+
- Docker (用于沙箱环境)
- LLM API Key (OpenAI, Anthropic, Google 等)

## 快速安装

### 方法 1: 官方安装脚本 (推荐)

```bash
curl -sSL https://strix.ai/install | bash
```

### 方法 2: 从源码安装

```bash
# 克隆仓库
git clone https://github.com/usestrix/strix.git
cd strix

# 安装依赖
pip install -e .

# 或者使用 uv (更快)
uv sync
```

### 方法 3: 使用 pip

```bash
pip install strix-agent
```

## 配置

```bash
# 设置 LLM 提供商和 API Key
export STRIX_LLM="openai/gpt-5.4"
export LLM_API_KEY="your-api-key"

# 可选：配置其他选项
export STRIX_SANDBOX_MODE="docker"  # 沙箱模式
```

## 运行扫描

```bash
# 扫描本地代码
strix --target ./app-directory

# 扫描远程 URL
strix --target https://your-app.com

# 扫描 GitHub 仓库
strix --target https://github.com/org/repo

# 非交互模式 (适合 CI/CD)
strix --target ./app --non-interactive
```

## 查看结果

```bash
# 打开最新扫描的 Web 界面
strix view

# 打开指定扫描
strix view my-run-name
```

## 生成合规报告

### 步骤 1: 创建测试用例模板

```python
from strix.tools.reporting.compliance_tools import create_test_case_template

await create_test_case_template(output_path="./test_cases.xlsx")
```

### 步骤 2: 编辑测试用例 (可选)

打开 `test_cases.xlsx`，根据需要修改测试用例。支持两种格式：

**简单格式 (6 列):**
- ID, Name, Category, Severity, Description, Remediation

**扩展格式 (12 列 - 您的格式):**
- 序号，用例名称，类型，前提条件，测试步骤，预期结果，基础分类，威胁类型，备注，版本，是否实现自动化，级别

### 步骤 3: 执行扫描

```bash
strix --target https://your-app.com
```

### 步骤 4: 生成合规报告

```python
from strix.tools.reporting.compliance_tools import generate_compliance_report

await generate_compliance_report(
    test_case_xlsx_path="./test_cases.xlsx",
    output_docx_path="./compliance_report.docx"
)
```

## 生成带截图的报告

Strix 现在支持自动生成 Burp Suite 风格和终端风格的截图：

```python
from strix.tools.reporting.tool import create_vulnerability_report

await create_vulnerability_report(
    title="SQL Injection",
    description="...",
    
    # 方式 1: 自动生成 Burp 截图
    http_request_for_screenshot={
        "method": "POST",
        "url": "http://target.com/api/login",
        "headers": {"Content-Type": "application/json"},
        "body": '{"username": "admin"}',
        "host": "target.com",
        "ip_address": "192.168.1.1"
    },
    
    # 方式 2: 自动生成终端截图
    tool_execution_for_screenshot={
        "tool_name": "sqlmap",
        "command": "sqlmap -u \"http://target.com/api?id=1\"",
        "output_lines": ["[*] Starting...", "[+] Found vulnerability"],
        "status": "Success",
        "tool_type": "SCANNING"
    }
)
```

## CI/CD 集成

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install Strix
        run: curl -sSL https://strix.ai/install | bash
      - name: Run Scan
        env:
          STRIX_LLM: openai/gpt-5.4
          LLM_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: strix --target ./ --non-interactive
```

## 故障排查

### Docker 问题
```bash
# 确保 Docker 正在运行
docker ps

# 拉取最新镜像
docker pull strixai/sandbox:latest
```

### 依赖问题
```bash
# 重新安装依赖
pip install --upgrade pip
pip install -e . --force-reinstall
```

### 查看日志
```bash
# 启用详细日志
export STRIX_LOG_LEVEL=debug
strix --target ./app
```

## 文件结构

```
strix/
├── strix/
│   ├── tools/
│   │   ├── reporting/
│   │   │   ├── tool.py              # 漏洞报告工具
│   │   │   ├── compliance_report.py # 合规报告生成
│   │   │   └── compliance_tools.py  # Agent 工具封装
│   │   └── screenshot/
│   │       ├── generator.py         # 截图生成器
│   │       ├── burp_template.html   # Burp UI 模板
│   │       └── terminal_template.html # 终端 UI 模板
│   └── report/
│       ├── state.py                 # 报告状态管理
│       └── writer.py                # Markdown 渲染
├── pyproject.toml
└── README.md
```

## 支持的功能

✅ Burp Suite 风格截图生成
✅ 终端风格截图生成
✅ XLSX 测试用例加载 (支持 6 列和 12 列格式)
✅ 智能漏洞匹配 (关键词+CWE)
✅ DOCX 合规报告生成
✅ 自定义整改建议
✅ 漏洞位置自动提取
✅ 中文支持 (微软雅黑字体)

## 联系方式

- 网站：https://strix.ai
- 文档：https://docs.strix.ai
- Discord: https://discord.gg/strix-ai
