## Cisco FTD Security Assessment MCP Server

This **Model Context Protocol (MCP)** server provides automated security assessments for Cisco Firepower Threat Defense (FTD) and Adaptive Security Appliance (ASA) infrastructures. It supports both live API interaction via Cisco Firepower Management Center (FMC) and offline analysis of configuration files.

---

## Core Features

- **Dual-Mode Operation:**
    
    - **LIVE Mode:** Connects directly to the Cisco FMC REST API to pull real-time device status, licensing info, and access policies.
        
    - **FILE Mode:** Parses standard `show running-config` text files using a robust regex-based engine.
        
- **Security Assessment Engine:** Automatically flags vulnerabilities across 10+ categories, including:
    
    - **Access Control:** Overly permissive rules (any/any), insecure protocols (Telnet), and unrestricted ICMP.
        
    - **VPN Crypto:** Detects weak encryption (DES/3DES), compromised integrity (MD5), and insecure DH groups.
        
    - **Management Plane:** Identifies unrestricted SSH/HTTP access and default SNMP community strings.
        
    - **Hygiene & Health:** Flags outdated software versions, missing licenses, and stale object groups.
        
- **Transport:** Uses standard I/O (stdio) for local process execution, ensuring no unnecessary network exposure.
    

---

## Installation

1. **Requirements:**
    
    - Python 3.10+
        
    - `requests`
        
    - `mcp` (FastMCP framework)
        
2. **Install Dependencies:**
    
    Bash
    
    ```
    pip install requests mcp urllib3
    ```
    

---

## ## Usage

#### ### Running as an MCP Server

To use this with an MCP-compatible client (like Claude Desktop), add the following to your configuration:

JSON

```
{
  "mcpServers": {
    "cisco-ftd-assessment": {
      "command": "python3",
      "args": ["path/to/cisco_ftd_mcp.py"]
    }
  }
}
```

#### Available Tools

| **Tool**               | **Description**                                       | **Key Parameters**                           |
| ---------------------- | ----------------------------------------------------- | -------------------------------------------- |
| **`connect_fmc`**      | Authenticates with FMC and performs a live audit.     | `host`, `username`, `password`, `verify_ssl` |
| **`load_config_file`** | Analyzes a local `.txt` or `.cfg` configuration file. | `file_path`                                  |

---

## Assessment Categories

The engine performs deep-dive checks into the following configuration blocks:

- **NAT Rules:** Detects internal hosts statically exposed to the outside.
    
- **Logging:** Validates if logging is enabled, buffered levels are sufficient, and external syslog servers are defined.
    
- **NTP:** Checks for time-drift vulnerabilities and unauthenticated time sources.
    
- **Interfaces:** Identifies misconfigured security levels (e.g., Level 0 on trusted zones).
    
- **Remote Access VPN:** Ensures idle timeouts are enforced on group policies.
    

---

## Data Model

The server utilizes a structured `ParsedConfig` dataclass to normalize data from both API and File sources, allowing the assessment engine to provide consistent findings regardless of the input method.

> **Note:** This tool is intended for security auditing and compliance checks. Always verify findings manually before implementing changes in production environments.
