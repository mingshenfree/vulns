"""Reporting tools for compliance mapping and DOCX report generation."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool


logger = logging.getLogger(__name__)


@function_tool(timeout=300, strict_mode=False)
async def generate_compliance_report(
    ctx: RunContextWrapper,
    test_case_xlsx_path: str,
    output_docx_path: str | None = None,
) -> dict[str, Any]:
    """Generate a compliance report by matching vulnerabilities to test cases.
    
    This tool loads test cases from an XLSX file, matches discovered 
    vulnerabilities to those test cases, and generates a DOCX format report
    following the specified template structure.
    
    **Report Template Structure**:
    
    For each test case, the report includes:
    
    ```
    [Section Number].[风险等级][严重程度]测试用例名称
    
    漏洞位置：
    <URL or API endpoint>
    
    漏洞及威胁描述：
    <Vulnerability description and threat impact>
    
    测试结果：
    <Screenshots, evidence, PoC results>
    
    整改建议：
    <Remediation recommendations>
    ```
    
    **Workflow**:
    
    1. Load test cases from the provided XLSX file
    2. Retrieve all discovered vulnerabilities from the scan
    3. Match vulnerabilities to test cases using keyword/CWE matching
    4. Generate DOCX report with matched results
    5. Save screenshots and evidence in the report
    
    **Test Case XLSX Format**:
    
    Expected columns:
    - ID: Test case identifier (e.g., "TC-001")
    - Name: Test case name (e.g., "SQL 注入漏洞检查")
    - Category: Vulnerability category
    - Severity: Expected severity level
    - Description: Test case description
    - Remediation: Remediation guidance
    
    **Matching Strategy**:
    
    The tool uses intelligent matching to associate vulnerabilities with
    test cases:
    - Keyword matching between test case names and vulnerability titles
    - CWE code matching when available
    - Endpoint/URL pattern matching
    
    Args:
        test_case_xlsx_path: Path to the XLSX file containing test cases.
            Must be accessible from the current environment.
        output_docx_path: Optional. Path where the DOCX report will be saved.
            If not provided, defaults to `{run_dir}/compliance_report.docx`.
    
    Returns:
        A dictionary with:
        - success: Boolean indicating if report generation succeeded
        - report_path: Path to the generated DOCX file (if successful)
        - matched_count: Number of vulnerabilities matched to test cases
        - total_test_cases: Total number of test cases processed
        - error: Error message (if failed)
    
    Example usage::
    
        # After completing a penetration test scan
        await generate_compliance_report(
            test_case_xlsx_path="/path/to/test_cases.xlsx",
            output_docx_path="./reports/final_compliance_report.docx"
        )
    
    The generated report will include:
    - Executive summary with pass/fail statistics
    - Detailed findings for each test case
    - Burp Suite screenshots (if available from vulnerability reports)
    - Terminal output screenshots (if available)
    - Customized remediation advice per test case
    """
    try:
        from strix.report.state import get_global_report_state
        from strix.tools.reporting.compliance_report import (
            generate_compliance_report_docx,
            load_test_cases_from_xlsx,
            match_vulnerabilities_to_test_cases,
        )
        
        report_state = get_global_report_state()
        if report_state is None:
            return {
                "success": False,
                "error": "No global report state available. Run a scan first.",
            }
        
        # Load test cases from XLSX
        test_cases = load_test_cases_from_xlsx(test_case_xlsx_path)
        logger.info(f"Loaded {len(test_cases)} test cases from {test_case_xlsx_path}")
        
        # Get discovered vulnerabilities
        vulnerabilities = report_state.get_existing_vulnerabilities()
        logger.info(f"Found {len(vulnerabilities)} vulnerabilities to match")
        
        # Match vulnerabilities to test cases
        matches = match_vulnerabilities_to_test_cases(test_cases, vulnerabilities)
        
        # Prepare scan info
        scan_info = {
            "scan_time": report_state.start_time,
            "target": ", ".join(
                t.get("url", t.get("name", "Unknown"))
                for t in report_state.run_record.get("targets_info", [])
            ),
            "run_id": report_state.run_id,
        }
        
        # Determine output path
        if output_docx_path is None:
            run_dir = report_state.get_run_dir()
            output_docx_path = str(run_dir / "compliance_report.docx")
        
        # Generate DOCX report
        report_path = generate_compliance_report_docx(
            output_path=output_docx_path,
            test_cases=test_cases,
            matches=matches,
            scan_info=scan_info,
        )
        
        return {
            "success": True,
            "report_path": report_path,
            "matched_count": len(matches),
            "total_test_cases": len(test_cases),
            "passed_count": sum(1 for tc in test_cases if tc.status == "PASS"),
            "failed_count": len(matches),
        }
    
    except FileNotFoundError as e:
        logger.error(f"Test case file not found: {e}")
        return {
            "success": False,
            "error": f"Test case file not found: {e}",
        }
    except Exception as e:
        logger.exception("Compliance report generation failed")
        return {
            "success": False,
            "error": f"Failed to generate compliance report: {e!s}",
        }


@function_tool(timeout=60, strict_mode=False)
async def create_test_case_template(
    ctx: RunContextWrapper,
    output_path: str,
) -> dict[str, Any]:
    """Create a sample XLSX test case template file.
    
    This tool generates a template XLSX file with pre-populated test cases
    covering common vulnerability types. You can customize this template
    before running scans to define your testing scope.
    
    **Template Includes**:
    
    - SQL Injection testing (SQL 注入漏洞检查)
    - XSS Cross-Site Scripting (XSS 跨站脚本漏洞检查)
    - File Upload vulnerabilities (文件上传漏洞检查)
    - Access Control / Privilege Escalation (越权访问漏洞检查)
    - Sensitive Information Disclosure (敏感信息泄露检查)
    
    Each test case includes:
    - Unique ID for tracking
    - Descriptive name in Chinese
    - Category classification
    - Expected severity level
    - Detailed description of what to test
    - Recommended remediation steps
    
    Args:
        output_path: Path where the XLSX template will be saved.
            Should have .xlsx extension.
    
    Returns:
        A dictionary with:
        - success: Boolean indicating if template creation succeeded
        - template_path: Path to the created XLSX file
        - test_case_count: Number of test cases in the template
    
    Example usage::
    
        # Create a template to customize before scanning
        await create_test_case_template(
            output_path="./test_cases_custom.xlsx"
        )
        
        # Then edit the XLSX file to add/remove/modify test cases
        # Finally use it for compliance reporting
        await generate_compliance_report(
            test_case_xlsx_path="./test_cases_custom.xlsx"
        )
    """
    try:
        from strix.tools.reporting.compliance_report import (
            create_sample_test_case_xlsx,
        )
        
        template_path = create_sample_test_case_xlsx(output_path)
        
        return {
            "success": True,
            "template_path": template_path,
            "test_case_count": 5,  # Default template has 5 test cases
            "message": (
                f"Test case template created at {template_path}. "
                "Customize the test cases as needed, then use with "
                "generate_compliance_report tool."
            ),
        }
    
    except Exception as e:
        logger.exception("Test case template creation failed")
        return {
            "success": False,
            "error": f"Failed to create test case template: {e!s}",
        }
