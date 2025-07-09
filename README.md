```
████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗   ███████╗ ██████╗ ███╗   ██╗███████╗███╗   ███╗ ██████╗██████╗ 
╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝   ╚══███╔╝██╔═══██╗████╗  ██║██╔════╝████╗ ████║██╔════╝██╔══██╗
   ██║   ███████║██████╔╝█████╗  ███████║   ██║        ███╔╝ ██║   ██║██╔██╗ ██║█████╗  ██╔████╔██║██║     ██████╔╝
   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║       ███╔╝  ██║   ██║██║╚██╗██║██╔══╝  ██║╚██╔╝██║██║     ██╔═══╝ 
   ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ██╗███████╗╚██████╔╝██║ ╚████║███████╗██║ ╚═╝ ██║╚██████╗██║     
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝ ╚═════╝╚═╝     
```

# Threat.Zone MCP Server

A Model Context Protocol (MCP) server for the Threat.Zone API, built with FastMCP. This server provides LLMs with access to Threat.Zone's malware analysis capabilities through standardized MCP tools.

## Features

- **File Analysis**: Submit files for malware analysis including sandbox execution, static analysis, and CDR (Content Disarm and Reconstruction)
- **URL Analysis**: Analyze URLs for threats and malicious content
- **Submission Management**: Retrieve detailed analysis results, indicators, IoCs, and YARA rules
- **Network Analysis**: Access DNS queries, HTTP/TCP/UDP requests, and network threats
- **Report Generation**: Download sanitized files and HTML reports
- **User Management**: Get user information and submission limits

## Installation

### Using pip

```bash
pip install threatzone-mcp
```

### Using uv (recommended)

```bash
uv add threatzone-mcp
```

### Development Installation

```bash
git clone https://github.com/threat-zone/threatzonemcp.git
cd threatzonemcp
uv sync --dev
```

## Configuration

Set your Threat.Zone API credentials as environment variables:

```bash
export THREATZONE_API_KEY="your_api_key_here"
# Optional: For private tenants or on-premise deployments
export THREATZONE_API_URL="https://your-tenant.threat.zone"
```

Or create a `.env` file:

```env
THREATZONE_API_KEY=your_api_key_here
# Optional: Custom API URL (defaults to https://app.threat.zone)
THREATZONE_API_URL=https://your-tenant.threat.zone
```

### Supported Deployments

- **Public Cloud**: `https://app.threat.zone` (default)
- **Private Tenant**: `https://your-tenant.threat.zone`
- **On-Premise**: `https://your-server.company.com`

# Connecting Threat.Zone MCP Server to Claude Desktop

## Prerequisites

1. **Claude Desktop installed** - Download from [Claude Desktop](https://claude.ai/download)
2. **UV installed** - `brew install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`
3. **Threat.Zone API Key** - Get from [Threat.Zone Settings](https://app.threat.zone/settings/api-key)

## Setup Steps

### 1. Prepare the MCP Server

```bash
# Clone and setup the project
git clone <your-repo-url>
cd threatzonemcp

# Install with UV
uv venv
uv pip install -e .

# Test the server works
THREATZONE_API_KEY=your_key uv run threatzone-mcp
# Should start without errors
```

### 2. Configure Claude Desktop

#### Option A: Using UV (Recommended)

1. **Find your Claude Desktop config directory**:
   - **macOS**: `~/Library/Application Support/Claude/`
   - **Windows**: `%APPDATA%\Claude\`
   - **Linux**: `~/.config/Claude/`

2. **Create or edit `claude_desktop_config.json`**:
```json
{
  "mcpServers": {
    "threatzone": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/full/path/to/your/threatzonemcp",
        "threatzone-mcp"
             ],
       "env": {
         "THREATZONE_API_KEY": "your_actual_api_key_here",
         "THREATZONE_API_URL": "https://your-tenant.threat.zone"
       }
    }
  }
}
```

#### Option B: Using Python directly

```json
{
  "mcpServers": {
    "threatzone": {
      "command": "python",
      "args": [
        "-m",
        "threatzone_mcp.server"
      ],
      "cwd": "/full/path/to/your/threatzonemcp",
      "env": {
        "THREATZONE_API_KEY": "your_actual_api_key_here",
        "PYTHONPATH": "/full/path/to/your/threatzonemcp/src"
      }
    }
  }
}
```

#### Option C: Using virtual environment directly

```json
{
  "mcpServers": {
    "threatzone": {
      "command": "/full/path/to/your/threatzonemcp/.venv/bin/python",
      "args": [
        "-m",
        "threatzone_mcp.server"
      ],
      "cwd": "/full/path/to/your/threatzonemcp",
      "env": {
        "THREATZONE_API_KEY": "your_actual_api_key_here",
        "PYTHONPATH": "/full/path/to/your/threatzonemcp/src"
      }
    }
  }
}
```

### 3. Important Configuration Notes

1. **Replace placeholders**:
   - Replace `/full/path/to/your/threatzonemcp` with the actual full path
   - Replace `your_actual_api_key_here` with your Threat.Zone API key

2. **Get the full path**:
```bash
cd threatzonemcp
pwd  # This shows the full path
```

3. **Verify API key**: Make sure your API key is valid by testing:
```bash
# For public cloud (default)
curl -H "Authorization: Bearer your_api_key" https://app.threat.zone/public-api/me

# For private tenant or on-premise
curl -H "Authorization: Bearer your_api_key" https://your-tenant.threat.zone/public-api/me
```

4. **API URL Configuration** (Optional):
   - **Public Cloud**: No need to set `THREATZONE_API_URL` (uses default)
   - **Private Tenant**: Set `THREATZONE_API_URL=https://your-tenant.threat.zone` 
   - **On-Premise**: Set `THREATZONE_API_URL=https://your-server.company.com`

### 4. Restart Claude Desktop

After saving the configuration:
1. **Quit Claude Desktop completely**
2. **Restart Claude Desktop**
3. **Look for the 🔌 icon** in a new chat to confirm MCP servers are connected

### 5. Test the Connection

In Claude Desktop, try asking:

> "Can you get my Threat.Zone user information?"

or

> "What are the available threat levels in Threat.Zone?"

Claude should be able to use the MCP tools to interact with the Threat.Zone API.

## Troubleshooting

### Common Issues

1. **"Server not found" error**:
   - Check the full path is correct
   - Verify UV is installed and in PATH
   - Test the command manually: `uv run --directory /path/to/threatzonemcp threatzone-mcp`

2. **"API key required" error**:
   - Verify the API key is set correctly in the env section
   - Test the API key works with curl

3. **"Permission denied" error**:
   - Make sure the script is executable
   - Check file permissions

4. **Python import errors**:
   - Verify the virtual environment is properly set up
   - Check PYTHONPATH includes the src directory



## Available Tools

Once connected, Claude will have access to these Threat.Zone tools:

### Analysis Tools
- **URL Analysis**: `scan_url` - Analyze URLs for threats
- **File Analysis**: 
  - `scan_file_sandbox` - Advanced sandbox analysis with full configuration
  - `scan_file_sandbox_simple` - Simple sandbox analysis with defaults
  - `scan_file_static` - Static file analysis  
  - `scan_file_cdr` - Content Disarm and Reconstruction

### Results & Monitoring
- **Submission Details**: `get_submission`, `get_submission_status_summary`
- **Threat Intelligence**: `get_submission_indicators`, `get_submission_iocs`
- **Detection Rules**: `get_submission_yara_rules`, `get_submission_varist_results`
- **Network Activity**: `get_submission_dns`, `get_submission_http`, `get_submission_tcp`, `get_submission_udp`, `get_submission_network_threats`
- **Artifacts**: `get_submission_artifacts`, `get_submission_config_extractor`

### Helper Functions
- **Status Interpretation**: `interpret_status`, `interpret_threat_level`
- **Constants**: `get_metafields`, `get_levels`, `get_statuses`, `get_sample_metafield`

### User Management
- **Account Info**: `get_user_info`
- **Submission History**: `get_my_submissions`, `get_public_submissions`
- **Search**: `search_by_hash`

### Downloads
- **Files**: `download_sanitized_file` (CDR-cleaned files)
- **Reports**: `download_html_report` (detailed analysis reports)

## Example Claude Conversations

Once connected, you can ask Claude things like:

> "Analyze this suspicious PDF file with Windows 11 environment and internet access enabled"

> "Check the status of my recent submissions and show me any that found malware"

> "What are the network connections and DNS queries from submission UUID abc-123?"

> "Download the analysis report for my latest submission"

> "Monitor submission progress and notify me when analysis is complete"

Claude will use the appropriate MCP tools to interact with Threat.Zone and provide comprehensive malware analysis insights! 

## Usage

### Running the Server

```bash
# Using the installed script
threatzone-mcp

# Or directly with Python
python -m threatzone_mcp.server
```

### Available Tools

The server provides the following MCP tools:

#### Constants & Helpers
- `get_metafields()` - Get available metafields for advanced configuration
- `get_levels()` - Get threat levels
- `get_statuses()` - Get submission statuses
- `get_sample_metafield()` - Get sample configuration for sandbox analysis
- `interpret_status(status_value)` - Convert numeric status to human-readable description
- `interpret_threat_level(level_value)` - Convert numeric threat level to description
- `get_submission_status_summary(uuid)` - Get submission with interpreted status and threat level
- `get_server_config()` - Get current server configuration and connection status

#### User Information
- `get_user_info()` - Get current user information and limits

#### Scanning
- `scan_url(url, is_public=False)` - Analyze a URL
- `scan_file_sandbox(file_path, ...)` - Submit file for advanced sandbox analysis with full configuration
- `scan_file_sandbox_simple(file_path, is_public=False, entrypoint=None, password=None)` - Submit file for sandbox analysis with default settings
- `scan_file_static(file_path, is_public=False, entrypoint=None, password=None)` - Submit file for static analysis
- `scan_file_cdr(file_path, is_public=False, entrypoint=None, password=None)` - Submit file for CDR processing

#### Submission Retrieval
- `get_submission(uuid)` - Get submission details
- `get_submission_indicators(uuid)` - Get submission indicators
- `get_submission_iocs(uuid)` - Get Indicators of Compromise
- `get_submission_yara_rules(uuid)` - Get matched YARA rules
- `get_submission_varist_results(uuid)` - Get Varist Hybrid Analyzer results
- `get_submission_artifacts(uuid)` - Get analysis artifacts
- `get_submission_config_extractor(uuid)` - Get extracted configurations

#### Network Analysis
- `get_submission_dns(uuid)` - Get DNS queries
- `get_submission_http(uuid)` - Get HTTP requests
- `get_submission_tcp(uuid)` - Get TCP requests
- `get_submission_udp(uuid)` - Get UDP requests
- `get_submission_network_threats(uuid)` - Get network threats

#### User Submissions
- `get_my_submissions(page=1, jump=10)` - Get user's submissions
- `get_public_submissions(page=1, jump=10)` - Get public submissions
- `search_by_hash(hash, page=1, jump=10)` - Search submissions by hash

#### Downloads
- `download_sanitized_file(uuid)` - Download CDR-sanitized file
- `download_html_report(uuid)` - Download HTML analysis report

## Advanced Sandbox Analysis

The `scan_file_sandbox` tool supports comprehensive configuration options for detailed malware analysis:

### Environment Options
- **Windows**: `w7_x64`, `w10_x64`, `w11_x64`
- **macOS**: `macos`  
- **Android**: `android`
- **Linux**: `linux`

### Analysis Configuration
- **Timeout**: 60, 120, 180, 240, or 300 seconds
- **Work Path**: `desktop`, `root`, `%AppData%`, `windows`, `temp`
- **Mouse Simulation**: Enable/disable user interaction simulation
- **Internet Connection**: Allow/block network access
- **HTTPS Inspection**: Monitor encrypted traffic
- **Raw Logs**: Include detailed execution logs
- **Snapshots**: Capture VM state during execution
- **Sleep Evasion**: Detect anti-analysis techniques
- **Smart Tracing**: Advanced behavioral analysis
- **Dump Collector**: Collect memory dumps

### Usage Examples

**Simple Analysis**:
```python
# Use default settings
await client.call_tool("scan_file_sandbox_simple", {
    "file_path": "/path/to/file.exe"
})
```

**Advanced Analysis**:
```python
# Full configuration control
await client.call_tool("scan_file_sandbox", {
    "file_path": "/path/to/file.exe",
    "environment": "w11_x64",
    "timeout": 300,
    "internet_connection": True,
    "https_inspection": True,
    "raw_logs": True,
    "modules": ["csi", "cdr"]
})
```

See `examples/advanced_sandbox_example.py` for detailed usage examples.

## Understanding Results

### Submission Status Values
The API returns numeric status codes that indicate the current state of your submission:

| Value | Status | Description |
|-------|--------|-------------|
| 1 | File received | File has been uploaded and queued for analysis |
| 2 | Submission failed | Analysis failed due to error or timeout |
| 3 | Submission running | Analysis is currently in progress |
| 4 | Submission VM ready | Virtual machine is prepared and starting analysis |
| 5 | Submission finished | Analysis completed successfully |

### Threat Level Values
Analysis results include a threat level indicating the severity of findings:

| Value | Level | Description |
|-------|-------|-------------|
| 0 | Unknown | Unable to determine threat level |
| 1 | Informative | File appears benign with some notable behaviors |
| 2 | Suspicious | File exhibits potentially malicious characteristics |
| 3 | Malicious | File confirmed as malware or highly dangerous |

### Usage Examples

**Check submission status**:
```python
# Get raw status
submission = await client.call_tool("get_submission", {"uuid": "submission_id"})
print(f"Status code: {submission['status']}")

# Get interpreted status
summary = await client.call_tool("get_submission_status_summary", {"uuid": "submission_id"})
print(f"Status: {summary['status_description']}")
print(f"Threat Level: {summary['threat_level_description']}")
```

**Monitor analysis progress**:
```python
import asyncio

async def wait_for_analysis(uuid):
    while True:
        summary = await client.call_tool("get_submission_status_summary", {"uuid": uuid})
        status = summary.get('status')
        
        if status == 5:  # Finished
            print(f"Analysis complete! Threat level: {summary['threat_level_description']}")
            break
        elif status == 2:  # Failed
            print("Analysis failed")
            break
        else:
            print(f"Status: {summary['status_description']}")
            await asyncio.sleep(10)  # Wait 10 seconds before checking again
```

## API Reference

All tools follow the Threat.Zone API specification. For detailed parameter descriptions and response formats, refer to the [Threat.Zone API documentation](https://app.threat.zone/public-api/docs).

## Error Handling

The server includes comprehensive error handling for:
- Authentication failures (401)
- Invalid requests (400/422)
- Not found errors (404)
- Rate limiting
- Network issues

## License

GPL v3 License. See [LICENSE](LICENSE) for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For issues and questions:
- [GitHub Issues](https://github.com/threat-zone/threatzonemcp/issues)
- [Threat.Zone Documentation](https://threat.zone/docs)
- Email: info@malwation.com 