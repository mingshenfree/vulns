# 合规报告生成工具使用说明

## 概述

本工具集为 Strix 项目添加了基于测试用例的合规性报告生成功能，支持：
1. 从 XLSX 文件加载测试用例
2. 将发现的漏洞与测试用例智能匹配
3. 生成符合指定模板的 DOCX 格式报告

## 功能特性

### 1. 测试用例管理

**创建测试用例模板**：
```python
await create_test_case_template(
    output_path="./test_cases.xlsx"
)
```

生成的 XLSX 文件包含以下预定义测试用例：
- SQL 注入漏洞检查
- XSS 跨站脚本漏洞检查
- 文件上传漏洞检查
- 越权访问漏洞检查
- 敏感信息泄露检查

**XLSX 文件格式**：
| 列名 | 说明 | 示例 |
|------|------|------|
| ID | 测试用例唯一标识 | TC-001 |
| Name | 测试用例名称 | SQL 注入漏洞检查 |
| Category | 漏洞类别 | Injection |
| Severity | 预期严重程度 | High |
| Description | 测试描述 | 检查应用程序是否存在 SQL 注入漏洞... |
| Remediation | 整改建议 | 1、使用参数化查询... |

### 2. 合规报告生成

**生成 DOCX 报告**：
```python
await generate_compliance_report(
    test_case_xlsx_path="./test_cases.xlsx",
    output_docx_path="./reports/compliance_report.docx"
)
```

### 3. 报告模板结构

生成的 DOCX 报告遵循以下结构：

```
[章节号].[风险等级][严重程度]测试用例名称

漏洞位置：
<URL 或 API 端点>

漏洞及威胁描述：
<漏洞描述和威胁影响>

测试结果：
<截图、证据、PoC 结果>

整改建议：
<定制化修复建议>
```

**示例输出**：
```
1.1[存在风险][高危]SQL 注入漏洞检查

漏洞位置：
/api/login

漏洞及威胁描述：
The login endpoint is vulnerable to SQL injection attacks.
影响：Attackers can bypass authentication and access user data.

测试结果：
❌ 未通过 - 发现漏洞
证据：POST /api/login with payload admin' OR 1=1-- returned admin access
验证截图：
- Burp Suite SQL Injection Request: /path/to/screenshot.png

整改建议：
1、增加对客户端提交数据的合法性验证，至少严格过滤 SQL 语句中的关键字...
```

## 工作流程

### 完整使用流程

1. **准备阶段** - 创建或自定义测试用例：
   ```python
   # 创建默认模板
   await create_test_case_template(output_path="./test_cases.xlsx")
   
   # （可选）手动编辑 XLSX 文件，添加/修改测试用例
   ```

2. **执行扫描** - 运行 Strix 渗透测试：
   ```bash
   strix scan --target https://example.com
   ```

3. **生成报告** - 匹配漏洞并生成 DOCX：
   ```python
   await generate_compliance_report(
       test_case_xlsx_path="./test_cases.xlsx",
       output_docx_path="./final_report.docx"
   )
   ```

### 自动化集成

在 Agent 工作流中自动调用：

```python
# 在扫描完成后自动生成合规报告
from strix.report.state import get_global_report_state

report_state = get_global_report_state()
if report_state and report_state.scan_results:
    result = await generate_compliance_report(
        test_case_xlsx_path="/path/to/test_cases.xlsx"
    )
    if result["success"]:
        print(f"Report generated: {result['report_path']}")
        print(f"Matched {result['matched_count']}/{result['total_test_cases']} test cases")
```

## 智能匹配机制

工具使用以下策略将漏洞与测试用例匹配：

1. **关键词匹配** (权重 0.3)
   - 从测试用例名称提取关键词（如"SQL"、"注入"、"XSS"）
   - 匹配漏洞标题和描述

2. **CWE 代码匹配** (权重 0.5)
   - 如果测试用例描述中包含 CWE 代码
   - 与漏洞的 CWE 字段精确匹配

3. **标题包含匹配** (权重 0.2)
   - 测试用例关键词出现在漏洞标题中

**匹配阈值**：综合得分 ≥ 0.3 视为有效匹配

## 截图支持

报告自动包含之前生成的 Burp Suite 和终端截图：

- **Burp Suite 截图**：通过 `http_request_for_screenshot` 参数自动生成
- **终端截图**：通过 `tool_execution_for_screenshot` 参数自动生成

这些截图会在"验证截图"部分显示，提供直观的漏洞证明。

## API 参考

### `create_test_case_template(ctx, output_path)`

创建示例 XLSX 测试用例模板。

**参数**：
- `output_path` (str): 输出文件路径（应以 .xlsx 结尾）

**返回**：
```json
{
  "success": true,
  "template_path": "/path/to/template.xlsx",
  "test_case_count": 5,
  "message": "..."
}
```

### `generate_compliance_report(ctx, test_case_xlsx_path, output_docx_path)`

生成合规性 DOCX 报告。

**参数**：
- `test_case_xlsx_path` (str): XLSX 测试用例文件路径
- `output_docx_path` (str, optional): 输出 DOCX 路径，默认为 `{run_dir}/compliance_report.docx`

**返回**：
```json
{
  "success": true,
  "report_path": "/path/to/report.docx",
  "matched_count": 2,
  "total_test_cases": 5,
  "passed_count": 3,
  "failed_count": 2
}
```

## 依赖项

确保已安装以下 Python 包：
```bash
pip install openpyxl python-docx
```

## 注意事项

1. **中文支持**：报告使用"微软雅黑"字体，确保系统已安装该字体
2. **截图路径**：截图文件必须是可访问的本地路径
3. **测试用例唯一性**：每个漏洞只匹配一个测试用例（先到先得）
4. **未匹配处理**：未匹配到漏洞的测试用例标记为"通过"状态
