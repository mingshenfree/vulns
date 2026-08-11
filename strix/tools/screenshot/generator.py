"""
Screenshot generation tools for vulnerability reports.

This module provides tools to generate Burp Suite-style and Terminal-style
screenshots using agent-browser for inclusion in vulnerability reports.
"""

import os
import tempfile
import base64
from pathlib import Path
from typing import Optional, Dict, Any, List
from jinja2 import Template


def ensure_directory_exists(path: str) -> None:
    """Ensure directory exists, create if not."""
    Path(path).mkdir(parents=True, exist_ok=True)


# Load HTML templates - use absolute paths from strix/report directory
REPORT_DIR = Path(__file__).parent.parent.parent / "report"
BURP_TEMPLATE_PATH = REPORT_DIR / "burp_template.html"
TERMINAL_TEMPLATE_PATH = REPORT_DIR / "terminal_template.html"


def load_template(template_path: Path) -> Template:
    """Load HTML template from file."""
    with open(template_path, 'r', encoding='utf-8') as f:
        return Template(f.read())


def escape_html(text: str) -> str:
    """Escape HTML special characters."""
    if not text:
        return ""
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


def format_headers(headers: Dict[str, str]) -> str:
    """Format HTTP headers as HTML."""
    html_lines = []
    for name, value in headers.items():
        html_lines.append(
            f'<div><span class="header-name">{escape_html(name)}:</span> '
            f'<span class="header-value">{escape_html(value)}</span></div>'
        )
    return "\n".join(html_lines)


def create_burp_html(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str] = None,
    host: str = "",
    ip_address: str = "",
    vulnerability_type: Optional[str] = None,
    status_code: Optional[int] = None,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
) -> str:
    """
    Generate Burp Suite-style HTML for an HTTP request/response.
    
    Args:
        method: HTTP method (GET, POST, etc.)
        url: Full URL or path
        headers: Request headers dict
        body: Request body (optional)
        host: Target host
        ip_address: Resolved IP address
        vulnerability_type: Type of vulnerability detected (SQL Injection, XSS, etc.)
        status_code: Response status code (optional)
        response_headers: Response headers (optional)
        response_body: Response body (optional)
    
    Returns:
        Complete HTML string
    """
    template = load_template(BURP_TEMPLATE_PATH)
    
    # Parse URL
    from urllib.parse import urlparse
    parsed = urlparse(url)
    url_path = parsed.path or "/"
    if parsed.query:
        url_path += f"?{parsed.query}"
    
    # Format headers
    headers_html = format_headers(headers)
    
    # Create body section if present
    body_section_html = ""
    if body:
        body_content = escape_html(body)
        
        # Auto-highlight potential injection points
        if vulnerability_type and vulnerability_type.lower() in ["sql injection", "sqli"]:
            # Highlight SQL keywords and payloads
            for pattern in ["'", '"', "--", "UNION", "SELECT", "OR 1=1", "AND 1=1"]:
                if pattern.lower() in body.lower():
                    body_content = body_content.replace(
                        pattern, 
                        f'<span class="highlight-injection">{pattern}</span>'
                    )
        
        body_section_html = f"""
        <div class="body-section">
            <div class="body-title">Request Body</div>
            <div class="body-content">{body_content}</div>
        </div>
        """
    
    # Prepare template variables
    context = {
        "METHOD": method.upper(),
        "METHOD_LOWER": method.lower(),
        "URL_PATH": escape_html(url_path),
        "URL_FULL": escape_html(url),
        "HEADERS_HTML": headers_html,
        "BODY_SECTION_HTML": body_section_html,
        "BODY_RAW": escape_html(body or ""),
        "HOST": escape_html(host or parsed.netloc),
        "IP_ADDRESS": ip_address or "N/A",
        "CONTENT_LENGTH": len(body) if body else 0,
        "VULNERABILITY_TYPE": vulnerability_type or "",
    }
    
    return template.render(**context)


def create_terminal_html(
    tool_name: str,
    command: str,
    output_lines: List[str],
    execution_time: str = "0.0s",
    status: str = "Success",
    hostname: str = "strix-agent",
    shell_type: str = "bash",
    tool_type: str = "SCANNING",
) -> str:
    """
    Generate Terminal-style HTML for tool execution output.
    
    Args:
        tool_name: Name of the tool executed
        command: Command that was run
        output_lines: List of output lines
        execution_time: Execution time string
        status: Execution status (Success, Failed, etc.)
        hostname: Hostname to display
        shell_type: Shell type (bash, zsh, etc.)
        tool_type: Type of tool (SCANNING, EXPLOITATION, RECON, etc.)
    
    Returns:
        Complete HTML string
    """
    template = load_template(TERMINAL_TEMPLATE_PATH)
    
    # Format output lines with appropriate styling
    output_html_lines = []
    for line in output_lines:
        line_escaped = escape_html(line)
        
        # Auto-detect line type for coloring
        css_class = "output-normal"
        line_lower = line.lower()
        
        if "error" in line_lower or "failed" in line_lower or "exception" in line_lower:
            css_class = "output-error"
        elif "success" in line_lower or "found" in line_lower or "vulnerability" in line_lower:
            css_class = "output-success"
        elif "warning" in line_lower or "warn" in line_lower:
            css_class = "output-warning"
        elif "info" in line_lower or "[*]" in line or "[+]" in line:
            css_class = "output-info"
        
        output_html_lines.append(
            f'<div class="output-line {css_class}">{line_escaped}</div>'
        )
    
    output_lines_html = "\n".join(output_html_lines)
    
    # Count total lines
    line_count = len(output_lines) + 1  # +1 for command line
    
    # Determine prompt based on shell
    prompt = f"user@{hostname}:~$" if shell_type == "bash" else f"% {hostname}"
    
    context = {
        "TOOL_NAME": escape_html(tool_name),
        "TOOL_TYPE": escape_html(tool_type),
        "COMMAND": escape_html(command),
        "OUTPUT_LINES_HTML": output_lines_html,
        "EXECUTION_TIME": execution_time,
        "STATUS": escape_html(status),
        "HOSTNAME": escape_html(hostname),
        "SHELL_TYPE": shell_type.upper(),
        "LINE_COUNT": line_count,
        "PROMPT": escape_html(prompt),
    }
    
    return template.render(**context)


async def capture_screenshot_from_html(
    html_content: str,
    output_path: str,
    viewport_width: int = 1280,
    viewport_height: int = 720,
    full_page: bool = False,
) -> Dict[str, Any]:
    """
    Use agent-browser to capture a screenshot from HTML content.
    
    This function:
    1. Saves HTML to a temporary file
    2. Opens it in agent-browser
    3. Captures a screenshot
    4. Returns the screenshot path and metadata
    
    Args:
        html_content: HTML content to render
        output_path: Path to save the screenshot
        viewport_width: Browser viewport width
        viewport_height: Browser viewport height
        full_page: Whether to capture full page or just viewport
    
    Returns:
        Dict with screenshot path, base64 data, and metadata
    """
    import asyncio
    from strix.tools.browser.agent_browser import AgentBrowserTool
    
    # Create temporary directory for HTML file
    temp_dir = tempfile.mkdtemp(prefix="strix_screenshot_")
    html_file = os.path.join(temp_dir, "preview.html")
    
    # Save HTML content
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    # Create file URL
    file_url = f"file://{html_file}"
    
    try:
        # Initialize agent-browser tool
        browser_tool = AgentBrowserTool()
        
        # Navigate to the HTML file
        await browser_tool.navigate(file_url)
        
        # Wait for page to fully render
        await asyncio.sleep(1.5)
        
        # Capture screenshot
        screenshot_result = await browser_tool.screenshot(
            output_path=output_path,
            full_page=full_page,
        )
        
        # Read screenshot as base64
        with open(output_path, 'rb') as f:
            screenshot_base64 = base64.b64encode(f.read()).decode('utf-8')
        
        return {
            "path": output_path,
            "base64": screenshot_base64,
            "width": viewport_width,
            "height": viewport_height,
            "format": "png",
            "file_url": file_url,
        }
    
    except Exception as e:
        # Fallback: save HTML directly and return error info
        return {
            "path": output_path,
            "error": str(e),
            "html_file": html_file,
            "base64": None,
        }
    finally:
        # Note: We don't clean up temp files immediately to allow debugging
        pass


async def generate_burp_screenshot(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[str] = None,
    vulnerability_type: Optional[str] = None,
    output_filename: Optional[str] = None,
    host: str = "",
    ip_address: str = "",
    status_code: Optional[int] = None,
    response_headers: Optional[Dict[str, str]] = None,
    response_body: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Generate a Burp Suite-style screenshot for a vulnerability.
    
    Args:
        method: HTTP method
        url: Target URL
        headers: Request headers
        body: Request body
        vulnerability_type: Type of vulnerability
        output_filename: Output filename (auto-generated if not provided)
        host: Target host
        ip_address: Resolved IP
        status_code: Response status code
        response_headers: Response headers
        response_body: Response body
    
    Returns:
        Screenshot result dict
    """
    # Generate output filename if not provided
    if not output_filename:
        timestamp = Path(tempfile.gettempdir()).stat().st_mtime
        output_filename = f"burp_screenshot_{int(timestamp)}.png"
    
    # Ensure screenshots directory exists
    screenshots_dir = Path(output_filename).parent
    ensure_directory_exists(str(screenshots_dir))
    
    # Generate HTML
    html_content = create_burp_html(
        method=method,
        url=url,
        headers=headers,
        body=body,
        host=host,
        ip_address=ip_address,
        vulnerability_type=vulnerability_type,
        status_code=status_code,
        response_headers=response_headers,
        response_body=response_body,
    )
    
    # Capture screenshot
    result = await capture_screenshot_from_html(
        html_content=html_content,
        output_path=str(Path(output_filename).absolute()),
    )
    
    # Add metadata
    result["metadata"] = {
        "type": "burp_suite",
        "method": method,
        "url": url,
        "vulnerability_type": vulnerability_type,
    }
    
    return result


async def generate_terminal_screenshot(
    tool_name: str,
    command: str,
    output_lines: List[str],
    output_filename: Optional[str] = None,
    execution_time: str = "0.0s",
    status: str = "Success",
    tool_type: str = "SCANNING",
) -> Dict[str, Any]:
    """
    Generate a Terminal-style screenshot for tool execution.
    
    Args:
        tool_name: Name of the tool
        command: Executed command
        output_lines: Output lines from tool
        output_filename: Output filename (auto-generated if not provided)
        execution_time: Execution time
        status: Execution status
        tool_type: Tool type category
    
    Returns:
        Screenshot result dict
    """
    # Generate output filename if not provided
    if not output_filename:
        timestamp = Path(tempfile.gettempdir()).stat().st_mtime
        safe_tool_name = "".join(c for c in tool_name if c.isalnum() or c in "-_").lower()
        output_filename = f"terminal_{safe_tool_name}_{int(timestamp)}.png"
    
    # Ensure screenshots directory exists
    screenshots_dir = Path(output_filename).parent
    ensure_directory_exists(str(screenshots_dir))
    
    # Generate HTML
    html_content = create_terminal_html(
        tool_name=tool_name,
        command=command,
        output_lines=output_lines,
        execution_time=execution_time,
        status=status,
        tool_type=tool_type,
    )
    
    # Capture screenshot
    result = await capture_screenshot_from_html(
        html_content=html_content,
        output_path=str(Path(output_filename).absolute()),
    )
    
    # Add metadata
    result["metadata"] = {
        "type": "terminal",
        "tool_name": tool_name,
        "command": command,
        "status": status,
    }
    
    return result
