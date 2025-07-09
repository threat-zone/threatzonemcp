"""Threat.Zone MCP Server implementation."""

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import httpx
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Load environment variables
load_dotenv()

# Initialize FastMCP server
app = FastMCP("ThreatZone")

# Configuration
API_BASE_URL = os.getenv("THREATZONE_API_URL", "https://app.threat.zone")
API_KEY = os.getenv("THREATZONE_API_KEY")


class ThreatZoneError(Exception):
    """Custom exception for Threat.Zone API errors."""
    pass


class APIClient:
    """HTTP client for Threat.Zone API."""
    
    def __init__(self, api_key: str, base_url: str = API_BASE_URL):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make GET request to API."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                params=params
            )
            await self._handle_response(response)
            return response.json()
    
    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None, files: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make POST request to API."""
        async with httpx.AsyncClient() as client:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            if files:
                # For file uploads, don't set Content-Type
                response = await client.post(
                    f"{self.base_url}{endpoint}",
                    headers=headers,
                    data=data,
                    files=files
                )
            else:
                response = await client.post(
                    f"{self.base_url}{endpoint}",
                    headers=self.headers,
                    json=data
                )
            await self._handle_response(response)
            return response.json()
    
    async def download(self, endpoint: str) -> bytes:
        """Download file from API."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers
            )
            await self._handle_response(response)
            return response.content
    
    async def _handle_response(self, response: httpx.Response) -> None:
        """Handle API response errors."""
        if response.status_code == 401:
            raise ThreatZoneError("Authentication failed. Check your API key.")
        elif response.status_code == 404:
            raise ThreatZoneError("Resource not found.")
        elif response.status_code == 422:
            raise ThreatZoneError("Invalid request parameters.")
        elif response.status_code >= 400:
            try:
                error_data = response.json()
                error_msg = error_data.get("message", f"API error: {response.status_code}")
            except:
                error_msg = f"API error: {response.status_code}"
            raise ThreatZoneError(error_msg)


# Initialize API client (lazy initialization)
client = None

def get_client():
    """Get or create the API client."""
    global client
    if client is None:
        if not API_KEY:
            raise ThreatZoneError("THREATZONE_API_KEY environment variable is required")
        client = APIClient(API_KEY)
    return client


# Constants Tools
@app.tool
async def get_metafields() -> Dict[str, Any]:
    """Get available metafields for scan configuration."""
    return await get_client().get("/public-api/constants/metafields")


@app.tool
async def get_levels() -> Dict[str, Any]:
    """Get threat levels used in analysis results."""
    return await get_client().get("/public-api/constants/levels")


@app.tool
async def get_statuses() -> Dict[str, Any]:
    """Get submission statuses."""
    return await get_client().get("/public-api/constants/statuses")


@app.tool
async def get_sample_metafield() -> Dict[str, Any]:
    """Get sample metafield configuration for sandbox analysis."""
    return await get_client().get("/public-api/constants/samplemetafield")


@app.tool
async def interpret_status(status_value: int) -> str:
    """
    Interpret a numeric status value from submission results.
    
    Args:
        status_value: Numeric status value (1-5)
        
    Returns:
        Human-readable status description
    """
    status_map = {
        1: "File received",
        2: "Submission is failed", 
        3: "Submission is running",
        4: "Submission VM is ready",
        5: "Submission is finished"
    }
    return status_map.get(status_value, f"Unknown status: {status_value}")


@app.tool
async def interpret_threat_level(level_value: int) -> str:
    """
    Interpret a numeric threat level value from analysis results.
    
    Args:
        level_value: Numeric threat level (0-3)
        
    Returns:
        Human-readable threat level description
    """
    level_map = {
        0: "Unknown",
        1: "Informative", 
        2: "Suspicious",
        3: "Malicious"
    }
    return level_map.get(level_value, f"Unknown level: {level_value}")


@app.tool
async def get_submission_status_summary(uuid: str) -> Dict[str, Any]:
    """
    Get submission details with interpreted status and threat level.
    
    Args:
        uuid: Submission UUID
        
    Returns:
        Submission details with human-readable status and threat level
    """
    submission = await get_client().get(f"/public-api/get/submission/{uuid}")
    
    # Add interpreted values if available
    if 'status' in submission:
        submission['status_description'] = await interpret_status(submission['status'])
    
    if 'level' in submission:
        submission['threat_level_description'] = await interpret_threat_level(submission['level'])
    
    return submission


# User Information Tools
@app.tool
async def get_user_info() -> Dict[str, Any]:
    """Get current user information, workspace details, and usage limits."""
    return await get_client().get("/public-api/me")


@app.tool
async def get_server_config() -> Dict[str, Any]:
    """
    Get current server configuration including API URL and connection status.
    
    Returns:
        Configuration details including API URL, version, and status
    """
    config = {
        "api_url": API_BASE_URL,
        "version": "0.1.0",
        "api_key_configured": bool(API_KEY and len(API_KEY) > 10)
    }
    
    # Test connection if API key is available
    if config["api_key_configured"]:
        try:
            user_info = await get_client().get("/public-api/me")
            config["connection_status"] = "connected"
            config["workspace"] = user_info.get("userInfo", {}).get("workspace", {}).get("name", "Unknown")
        except Exception as e:
            config["connection_status"] = "failed"
            config["error"] = str(e)
    else:
        config["connection_status"] = "no_api_key"
    
    return config


# Scanning Tools
@app.tool
async def scan_url(url: str, is_public: bool = False) -> Dict[str, Any]:
    """
    Analyze a URL for threats and malicious content.
    
    Args:
        url: The URL to analyze
        is_public: Whether the scan results should be public
    """
    data = {
        "url": url,
        "isPublic": is_public
    }
    return await get_client().post("/public-api/scan/url", data=data)


@app.tool
async def scan_file_sandbox(
    file_path: str, 
    is_public: bool = False, 
    entrypoint: Optional[str] = None, 
    password: Optional[str] = None,
    environment: str = "w10_x64",
    timeout: int = 180,
    work_path: str = "desktop",
    mouse_simulation: bool = True,
    https_inspection: bool = False,
    internet_connection: bool = False,
    raw_logs: bool = False,
    snapshot: bool = False,
    sleep_evasion: bool = False,
    smart_tracing: bool = False,
    dump_collector: bool = False,
    open_in_browser: bool = False,
    extension_check: bool = True,
    modules: Optional[List[str]] = None,
    auto_config: bool = False
) -> Dict[str, Any]:
    """
    Submit a file for advanced sandbox analysis with detailed configuration.
    
    Args:
        file_path: Path to the file to analyze
        is_public: Whether the scan results should be public (default: False)
        entrypoint: File to execute within archive (if applicable)
        password: Password for archive files (if applicable)
        environment: Analysis environment - w7_x64, w10_x64, w11_x64, macos, android, linux (default: w10_x64)
        timeout: Analysis timeout in seconds - 60, 120, 180, 240, 300 (default: 180)
        work_path: Working directory - desktop, root, %AppData%, windows, temp (default: desktop)
        mouse_simulation: Enable mouse simulation (default: True)
        https_inspection: Enable HTTPS inspection (default: False)
        internet_connection: Enable internet connection (default: False)
        raw_logs: Include raw logs (default: False)
        snapshot: Take VM snapshots (default: False)
        sleep_evasion: Enable sleep evasion techniques (default: False)
        smart_tracing: Enable smart tracing (default: False)
        dump_collector: Enable dump collection (default: False)
        open_in_browser: Open files in browser (default: False)
        extension_check: Perform extension check (default: True)
        modules: Analysis modules to use, e.g., ["csi", "cdr"] (default: None)
        auto_config: Use automatic configuration (default: False)
    """
    if not Path(file_path).exists():
        raise ThreatZoneError(f"File not found: {file_path}")
    
    # Build the analyze configuration
    analyze_config = [
        {"metafieldId": "environment", "value": environment},
        {"metafieldId": "private", "value": not is_public},
        {"metafieldId": "timeout", "value": timeout},
        {"metafieldId": "work_path", "value": work_path},
        {"metafieldId": "mouse_simulation", "value": mouse_simulation},
        {"metafieldId": "https_inspection", "value": https_inspection},
        {"metafieldId": "internet_connection", "value": internet_connection},
        {"metafieldId": "raw_logs", "value": raw_logs},
        {"metafieldId": "snapshot", "value": snapshot},
        {"metafieldId": "sleep_evasion", "value": sleep_evasion},
        {"metafieldId": "smart_tracing", "value": smart_tracing},
        {"metafieldId": "dump_collector", "value": dump_collector},
        {"metafieldId": "open_in_browser", "value": open_in_browser}
    ]
    
    # Prepare form data
    data = {
        "analyzeConfig": json.dumps(analyze_config),
        "extensionCheck": str(extension_check).lower()
    }
    
    if entrypoint:
        data["entrypoint"] = entrypoint
    if password:
        data["password"] = password
    if modules:
        data["modules"] = ",".join(modules)
    
    # Build URL with auto parameter
    url = f"/public-api/scan/sandbox?auto={str(auto_config).lower()}"
    
    files = {"file": open(file_path, "rb")}
    try:
        return await get_client().post(url, data=data, files=files)
    finally:
        files["file"].close()


@app.tool
async def scan_file_sandbox_simple(
    file_path: str, 
    is_public: bool = False, 
    entrypoint: Optional[str] = None, 
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Submit a file for simple sandbox analysis using default settings.
    
    This is a simplified version of scan_file_sandbox with default configurations.
    Use scan_file_sandbox for advanced configuration options.
    
    Args:
        file_path: Path to the file to analyze
        is_public: Whether the scan results should be public (default: False)
        entrypoint: File to execute within archive (if applicable)
        password: Password for archive files (if applicable)
    """
    return await scan_file_sandbox(
        file_path=file_path,
        is_public=is_public,
        entrypoint=entrypoint,
        password=password,
        auto_config=True  # Use automatic configuration for simplicity
    )


@app.tool
async def scan_file_static(
    file_path: str, 
    is_public: bool = False, 
    entrypoint: Optional[str] = None, 
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Submit a file for static analysis.
    
    Args:
        file_path: Path to the file to analyze
        is_public: Whether the scan results should be public
        entrypoint: File to execute within archive (if applicable)
        password: Password for archive files (if applicable)
    """
    if not Path(file_path).exists():
        raise ThreatZoneError(f"File not found: {file_path}")
    
    data = {"isPublic": is_public}
    if entrypoint:
        data["entrypoint"] = entrypoint
    if password:
        data["password"] = password
    
    files = {"file": open(file_path, "rb")}
    try:
        return await get_client().post("/public-api/scan/static", data=data, files=files)
    finally:
        files["file"].close()


@app.tool
async def scan_file_cdr(
    file_path: str, 
    is_public: bool = False, 
    entrypoint: Optional[str] = None, 
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Submit a file for CDR (Content Disarm and Reconstruction) processing.
    
    Args:
        file_path: Path to the file to process
        is_public: Whether the scan results should be public
        entrypoint: File to execute within archive (if applicable)
        password: Password for archive files (if applicable)
    """
    if not Path(file_path).exists():
        raise ThreatZoneError(f"File not found: {file_path}")
    
    data = {"isPublic": is_public}
    if entrypoint:
        data["entrypoint"] = entrypoint
    if password:
        data["password"] = password
    
    files = {"file": open(file_path, "rb")}
    try:
        return await get_client().post("/public-api/scan/cdr", data=data, files=files)
    finally:
        files["file"].close()


# Submission Retrieval Tools
@app.tool
async def get_submission(uuid: str) -> Dict[str, Any]:
    """
    Get submission details by UUID.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}")


@app.tool
async def get_submission_indicators(uuid: str) -> Dict[str, Any]:
    """
    Get all indicators for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/indicators")


@app.tool
async def get_submission_iocs(uuid: str) -> Dict[str, Any]:
    """
    Get all Indicators of Compromise for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/iocs")


@app.tool
async def get_submission_yara_rules(uuid: str) -> Dict[str, Any]:
    """
    Get all matched YARA rules for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/matched-yara-rules")


@app.tool
async def get_submission_varist_results(uuid: str) -> Dict[str, Any]:
    """
    Get Varist Hybrid Analyzer results for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/varist-hybrid-analyzer-results")


@app.tool
async def get_submission_artifacts(uuid: str) -> Dict[str, Any]:
    """
    Get all artifacts for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/analysis-artifacts")


@app.tool
async def get_submission_config_extractor(uuid: str) -> Dict[str, Any]:
    """
    Get all extracted configurations for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/config-extractor-results")


# Network Analysis Tools
@app.tool
async def get_submission_dns(uuid: str) -> Dict[str, Any]:
    """
    Get all DNS queries for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/dns")


@app.tool
async def get_submission_http(uuid: str) -> Dict[str, Any]:
    """
    Get all HTTP requests and packets for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/http")


@app.tool
async def get_submission_tcp(uuid: str) -> Dict[str, Any]:
    """
    Get all TCP requests and packets for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/tcp")


@app.tool
async def get_submission_udp(uuid: str) -> Dict[str, Any]:
    """
    Get all UDP requests and packets for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/udp")


@app.tool
async def get_submission_network_threats(uuid: str) -> Dict[str, Any]:
    """
    Get all network threats for a specific submission.
    
    Args:
        uuid: Submission UUID
    """
    return await get_client().get(f"/public-api/get/submission/{uuid}/threats")


# User Submissions Tools
@app.tool
async def get_my_submissions(page: int = 1, jump: int = 10) -> Dict[str, Any]:
    """
    Get user's submissions with pagination.
    
    Args:
        page: Page number (default: 1)
        jump: Number of items per page (default: 10)
    """
    return await get_client().get(f"/public-api/get/my-submissions/{page}/{jump}")


@app.tool
async def get_public_submissions(page: int = 1, jump: int = 10) -> Dict[str, Any]:
    """
    Get public submissions with pagination.
    
    Args:
        page: Page number (default: 1)
        jump: Number of items per page (default: 10)
    """
    return await get_client().get(f"/public-api/get/public-submissions/{page}/{jump}")


@app.tool
async def search_by_hash(hash: str, page: int = 1, jump: int = 10) -> Dict[str, Any]:
    """
    Search submissions by file hash (MD5, SHA1, or SHA256).
    
    Args:
        hash: File hash to search for
        page: Page number (default: 1)
        jump: Number of items per page (default: 10)
    """
    return await get_client().get(f"/public-api/get/{hash}/{page}/{jump}")


# Download Tools
@app.tool
async def download_sanitized_file(uuid: str) -> str:
    """
    Download the CDR-sanitized file for a given submission UUID.
    
    Args:
        uuid: Submission UUID
        
    Returns:
        Base64-encoded file content
    """
    import base64
    content = await get_client().download(f"/public-api/download/cdr/{uuid}")
    return base64.b64encode(content).decode('utf-8')


@app.tool
async def download_html_report(uuid: str) -> str:
    """
    Download HTML analysis report for a submission.
    
    Args:
        uuid: Submission UUID
        
    Returns:
        HTML report content
    """
    content = await get_client().download(f"/public-api/download/html-report/{uuid}")
    return content.decode('utf-8')


def main() -> None:
    """Main entry point for the MCP server."""
    if not API_KEY:
        print("Error: THREATZONE_API_KEY environment variable is required")
        exit(1)
    
    print("Starting Threat.Zone MCP Server...")
    print(f"API URL: {API_BASE_URL}")
    print(f"API Key: {API_KEY[:8]}...")
    app.run()


if __name__ == "__main__":
    main() 