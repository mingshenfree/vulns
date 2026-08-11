# Strix Enhanced - 自动化渗透测试框架

基于原生 Strix 项目增强，支持 Burp Suite 风格截图、终端 CLI 截图、XLSX 测试用例管理及 DOCX 合规报告生成。

## 🚀 快速开始 (Docker 部署)

### 1. 克隆项目
```bash
git clone https://github.com/mingshenfree/vulns.git
cd vulns/strix
```

### 2. 创建必要目录
```bash
mkdir -p workspace test_cases reports screenshots
```

### 3. 配置环境变量
```bash
cp .env.example .env
# 编辑 .env 文件，填入你的 LLM_API_KEY
```

### 4. 构建并启动容器
```bash
# 构建镜像 (已优化中国大陆镜像源)
docker compose build

# 启动容器
docker compose up -d

# 查看日志
docker compose logs -f
```

### 5. 执行扫描测试
```bash
# 进入容器
docker compose exec strix bash

# 在容器内执行扫描
export DISPLAY=:99
strix --target https://example.com --header "Cookie: sessionid=xxx"

# 生成合规报告
python -c "
from strix.tools.reporting.compliance_tools import generate_compliance_report
import asyncio
asyncio.run(generate_compliance_report(
    test_case_xlsx_path='/app/test_cases/test_cases.xlsx',
    output_docx_path='/app/reports/compliance_report.docx'
))
"
```

### 6. 查看结果
扫描完成后，报告保存在：
- `./reports/` - DOCX 合规报告
- `./screenshots/` - Burp/终端截图
- `./workspace/` - 工作区文件

## 📋 功能特性

### ✅ Burp Suite 风格截图
自动生成带 Burp UI 样式的 HTTP 请求/响应截图，包含：
- 请求行、Headers、Body 面板
- 漏洞类型徽章 (SQL 注入、XSS 等)
- Payload 高亮显示

### ✅ 终端 CLI 截图
自动生成工具执行过程的终端界面截图，包含：
- VS Code 风格终端界面
- 彩色输出 (错误红色、成功绿色、警告黄色)
- 命令执行状态栏

### ✅ XLSX 测试用例管理
支持标准 Excel 格式测试用例，表头包含：
`序号，用例名称，类型，前提条件，测试步骤，预期结果，基础分类，威胁类型，备注，版本，是否实现自动化，级别`

系统自动根据**用例名称**进行智能匹配。

### ✅ DOCX 合规报告
按照指定模板生成 Word 报告：
```
[章节号].[风险等级][严重程度]测试用例名称

漏洞位置：
<URL/API 端点>

漏洞及威胁描述：
<详细描述>

测试结果：
<截图证据>

整改建议：
<定制化修复方案>
```

## 🛠️ 手动安装 (非 Docker)

```bash
# 创建虚拟环境
python3 -m venv venv
source venv/bin/activate

# 安装依赖
pip install -e .
pip install openpyxl python-docx playwright
playwright install chromium

# 运行扫描
strix --target https://example.com
```

## 🔐 安全提醒

1. **仅限授权测试**：仅对拥有合法权限的目标进行扫描
2. **API Key 安全**：不要将 `.env` 文件提交到 Git
3. **Token 管理**：定期更换 GitHub Token 和 LLM API Key

## 📄 许可证

MIT License

## 🙏 致谢

- 原项目：https://github.com/usestrix/strix
- Kali Linux: https://www.kali.org/
