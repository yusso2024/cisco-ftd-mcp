#!/usr/bin/env python3
"""
Cisco FTD Security Assessment MCP Server

Two modes:
  1. LIVE — connect to Cisco FMC REST API (connect_fmc tool)
  2. FILE — parse a 'show run' text config (load_config_file tool)

Transport: stdio (local process, no network exposure)
"""

import base64
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import requests
import urllib3

from mcp.server.fastmcp import FastMCP

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("cisco-ftd-mcp")

mcp = FastMCP(name="cisco-ftd-assessment")


# =========================================================================
#  DATA MODEL — shared between both modes
# =========================================================================

@dataclass
class ParsedConfig:
    source: str = ""
    hostname: str = ""
    asa_version: str = ""
    serial_number: str = ""
    hardware: str = ""
    interfaces: list = field(default_factory=list)
    objects: list = field(default_factory=list)
    object_groups: list = field(default_factory=list)
    access_lists: list = field(default_factory=list)
    nat_rules: list = field(default_factory=list)
    crypto_proposals: list = field(default_factory=list)
    ikev2_policies: list = field(default_factory=list)
    tunnel_groups: list = field(default_factory=list)
    logging_config: dict = field(default_factory=dict)
    ssh_access: list = field(default_factory=list)
    http_access: list = field(default_factory=list)
    snmp_config: dict = field(default_factory=dict)
    ntp_servers: list = field(default_factory=list)
    telnet_access: list = field(default_factory=list)
    users: list = field(default_factory=list)
    threat_detection: dict = field(default_factory=dict)
    vpn_remote_access: dict = field(default_factory=dict)
    access_groups: list = field(default_factory=list)
    routes: list = field(default_factory=list)
    raw_text: str = ""


# =========================================================================
#  MODE 1: FMC REST API CLIENT
# =========================================================================

class FMCClient:
    """Thin wrapper around the Cisco FMC REST API."""

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = f"https://{host}"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.domain_uuid: str | None = None
        self._authenticate(username, password)

    def _authenticate(self, username: str, password: str) -> None:
        """
        POST to /api/fmc_platform/v1/auth/generatetoken with Basic auth.
        FMC returns the access token + refresh token + domain UUID in
        *response headers* (not the body).
        """
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        resp = self.session.post(
            f"{self.base_url}/api/fmc_platform/v1/auth/generatetoken",
            headers={"Authorization": f"Basic {creds}"},
        )
        resp.raise_for_status()

        self.domain_uuid = resp.headers["DOMAIN_UUID"]
        self.session.headers.update({
            "X-auth-access-token": resp.headers["X-auth-access-token"],
            "X-auth-refresh-token": resp.headers["X-auth-refresh-token"],
            "Content-Type": "application/json",
        })
        logger.info("Authenticated to FMC at %s (domain %s)", self.base_url, self.domain_uuid)

    def refresh_token(self) -> None:
        """Refresh the access token when it expires (30 min default)."""
        resp = self.session.post(
            f"{self.base_url}/api/fmc_platform/v1/auth/refreshtoken",
            headers={"X-auth-refresh-token": self.session.headers["X-auth-refresh-token"]},
        )
        resp.raise_for_status()
        self.session.headers["X-auth-access-token"] = resp.headers["X-auth-access-token"]
        self.session.headers["X-auth-refresh-token"] = resp.headers["X-auth-refresh-token"]

    def get(self, endpoint: str, params: dict | None = None) -> dict:
        """
        GET /api/fmc_config/v1/domain/{domainUUID}/{endpoint}

        Callers pass just the resource path (e.g. "devices/devicerecords")
        — base URL and domain UUID are prepended automatically.
        """
        url = f"{self.base_url}/api/fmc_config/v1/domain/{self.domain_uuid}/{endpoint}"
        resp = self.session.get(url, params=params or {})
        resp.raise_for_status()
        return resp.json()


# =========================================================================
#  MODE 2: SHOW-RUN TEXT PARSER
# =========================================================================

WEAK_ENCRYPTION = {"des", "3des"}
WEAK_INTEGRITY = {"md5"}
WEAK_DH_GROUPS = {"1", "2", "5"}


def parse_ftd_config(text: str) -> ParsedConfig:
    cfg = ParsedConfig(source="file", raw_text=text)
    lines = text.splitlines()

    serial_match = re.search(r"Serial Number:\s*(.+)", text)
    if serial_match:
        cfg.serial_number = serial_match.group(1).strip()

    hw_match = re.search(r"Hardware:\s*(.+)", text)
    if hw_match:
        cfg.hardware = hw_match.group(1).strip()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("ASA Version"):
            cfg.asa_version = line.split()[-1] if len(line.split()) > 1 else ""

        elif line.startswith("hostname "):
            cfg.hostname = line.split(None, 1)[1]

        elif line.startswith("interface "):
            iface = _parse_interface(lines, i)
            cfg.interfaces.append(iface)
            i = iface["_end_line"]
            continue

        elif line.startswith("object network "):
            obj = _parse_object_network(lines, i)
            cfg.objects.append(obj)
            i = obj["_end_line"]
            continue

        elif line.startswith("object-group "):
            grp = _parse_object_group(lines, i)
            cfg.object_groups.append(grp)
            i = grp["_end_line"]
            continue

        elif line.startswith("access-list "):
            cfg.access_lists.append(_parse_acl_line(line))

        elif line.startswith("access-group "):
            cfg.access_groups.append(_parse_access_group(line))

        elif re.match(r"^nat \(", line) or ("nat (" in line and "static" in line) or ("nat (" in line and "dynamic" in line):
            cfg.nat_rules.append({"raw": line, "type": "inline"})

        elif line.startswith("crypto ipsec ikev2 ipsec-proposal "):
            proposal = _parse_crypto_proposal(lines, i)
            cfg.crypto_proposals.append(proposal)
            i = proposal["_end_line"]
            continue

        elif line.startswith("crypto ikev2 policy "):
            policy = _parse_ikev2_policy(lines, i)
            cfg.ikev2_policies.append(policy)
            i = policy["_end_line"]
            continue

        elif line.startswith("tunnel-group ") and "type " in line:
            tg = _parse_tunnel_group(lines, i)
            cfg.tunnel_groups.append(tg)
            i = tg["_end_line"]
            continue

        elif line.startswith("logging "):
            _parse_logging_line(line, cfg.logging_config)

        elif line.startswith("ssh ") and not line.startswith("ssh version") and not line.startswith("ssh timeout"):
            cfg.ssh_access.append(_parse_mgmt_access(line, "ssh"))

        elif line == "ssh version 2":
            cfg.logging_config["ssh_version"] = 2

        elif line.startswith("http ") and line != "http server enable":
            cfg.http_access.append(_parse_mgmt_access(line, "http"))

        elif line.startswith("snmp-server "):
            _parse_snmp_line(line, cfg.snmp_config)

        elif line.startswith("ntp server "):
            cfg.ntp_servers.append({"server": line.split()[2], "authenticated": "key" in line})

        elif line.startswith("telnet ") and not line.startswith("telnet timeout"):
            parts = line.split()
            if len(parts) >= 4:
                cfg.telnet_access.append({
                    "network": parts[1],
                    "mask": parts[2],
                    "interface": parts[3],
                })

        elif line.startswith("username "):
            parts = line.split()
            user = {"name": parts[1]}
            if "privilege" in line:
                priv_idx = parts.index("privilege")
                user["privilege"] = int(parts[priv_idx + 1])
            cfg.users.append(user)

        elif line.startswith("threat-detection "):
            cfg.threat_detection["enabled"] = True
            cfg.threat_detection.setdefault("features", []).append(line)

        elif line.startswith("route "):
            cfg.routes.append(_parse_route(line))

        elif line.startswith("group-policy ") and " attributes" in line:
            gp = _parse_group_policy_attrs(lines, i)
            cfg.vpn_remote_access["group_policy"] = gp
            i = gp["_end_line"]
            continue

        i += 1

    _collect_nat_from_objects(cfg)
    return cfg


def _parse_interface(lines: list[str], start: int) -> dict:
    header = lines[start].strip()
    name = header.split(None, 1)[1]
    iface = {"name": name, "nameif": "", "security_level": -1, "ip": "", "mask": "",
             "shutdown": False, "management_only": False}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if _is_block_end(raw):
            break
        if line.startswith("nameif "):
            iface["nameif"] = line.split(None, 1)[1]
        elif line.startswith("security-level "):
            iface["security_level"] = int(line.split()[-1])
        elif line.startswith("ip address "):
            parts = line.split()
            iface["ip"] = parts[2] if len(parts) > 2 else ""
            iface["mask"] = parts[3] if len(parts) > 3 else ""
        elif line == "shutdown":
            iface["shutdown"] = True
        elif line == "management-only":
            iface["management_only"] = True
        i += 1
    iface["_end_line"] = i
    return iface


def _is_indented(raw_line: str) -> bool:
    return raw_line.startswith(" ") or raw_line.startswith("\t")


def _is_block_end(raw_line: str) -> bool:
    stripped = raw_line.strip()
    if not stripped or stripped == "!":
        return False
    return not _is_indented(raw_line)


def _parse_object_network(lines: list[str], start: int) -> dict:
    name = lines[start].strip().split(None, 2)[2]
    obj = {"name": name, "type": "network", "value": "", "nat": None}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if _is_block_end(raw):
            break
        if line.startswith("subnet "):
            obj["value"] = line[7:]
            obj["subtype"] = "subnet"
        elif line.startswith("host "):
            obj["value"] = line[5:]
            obj["subtype"] = "host"
        elif line.startswith("nat "):
            obj["nat"] = line
        i += 1
    obj["_end_line"] = i
    return obj


def _parse_object_group(lines: list[str], start: int) -> dict:
    header_parts = lines[start].strip().split()
    grp = {"type": header_parts[1], "name": header_parts[2], "members": [], "description": ""}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if _is_block_end(raw):
            break
        if line.startswith("description "):
            grp["description"] = line.split(None, 1)[1]
        elif line.startswith("network-object "):
            grp["members"].append(line)
        elif line.startswith("port-object "):
            grp["members"].append(line)
        i += 1
    grp["_end_line"] = i
    return grp


def _parse_acl_line(line: str) -> dict:
    parts = line.split()
    acl = {
        "acl_name": parts[1],
        "type": parts[2] if len(parts) > 2 else "",
        "action": parts[3] if len(parts) > 3 else "",
        "protocol": parts[4] if len(parts) > 4 else "",
        "raw": line,
        "source": "",
        "destination": "",
        "port": "",
    }

    remainder = " ".join(parts[4:]) if len(parts) > 4 else ""
    acl["source_and_dest"] = remainder

    if "any any" in line:
        acl["source"] = "any"
        acl["destination"] = "any"
    elif line.count(" any ") >= 1 or line.endswith(" any"):
        if parts[5:6] == ["any"]:
            acl["source"] = "any"

    for p in parts:
        if p in ("eq", "range"):
            idx = parts.index(p)
            acl["port"] = " ".join(parts[idx:])
            break

    return acl


def _parse_access_group(line: str) -> dict:
    parts = line.split()
    return {
        "acl_name": parts[1] if len(parts) > 1 else "",
        "direction": parts[2] if len(parts) > 2 else "",
        "interface": parts[4] if len(parts) > 4 else "",
    }


def _parse_crypto_proposal(lines: list[str], start: int) -> dict:
    name = lines[start].strip().split()[-1]
    prop = {"name": name, "encryption": "", "integrity": ""}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if _is_block_end(raw):
            break
        if "encryption" in line:
            prop["encryption"] = line.split()[-1]
        if "integrity" in line:
            prop["integrity"] = line.split()[-1]
        i += 1
    prop["_end_line"] = i
    return prop


def _parse_ikev2_policy(lines: list[str], start: int) -> dict:
    priority = lines[start].strip().split()[-1]
    policy = {"priority": priority, "encryption": "", "integrity": "", "dh_group": "", "prf": "", "lifetime": ""}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if _is_block_end(raw):
            break
        if line.startswith("encryption "):
            policy["encryption"] = line.split()[-1]
        elif line.startswith("integrity "):
            policy["integrity"] = line.split()[-1]
        elif line.startswith("group "):
            policy["dh_group"] = line.split()[-1]
        elif line.startswith("prf "):
            policy["prf"] = line.split()[-1]
        elif line.startswith("lifetime "):
            policy["lifetime"] = line.split()[-1]
        i += 1
    policy["_end_line"] = i
    return policy


def _parse_tunnel_group(lines: list[str], start: int) -> dict:
    peer = lines[start].strip().split()[1]
    parts = lines[start].strip().split()
    tg = {"peer": peer, "type": parts[3] if len(parts) > 3 else "", "attributes": {}}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if not _is_indented(raw) and not line.startswith(f"tunnel-group {peer}"):
            break
        if line.startswith(f"tunnel-group {peer}") and ("ipsec-attributes" in line or "general-attributes" in line or "webvpn-attributes" in line):
            section = line.split()[-1]
            tg["attributes"][section] = []
            i += 1
            while i < len(lines):
                attr_raw = lines[i]
                attr_line = attr_raw.strip()
                if not attr_line or attr_line == "!":
                    i += 1
                    continue
                if _is_block_end(attr_raw):
                    break
                tg["attributes"][section].append(attr_line)
                i += 1
            continue
        i += 1
    tg["_end_line"] = i
    return tg


def _parse_logging_line(line: str, log_cfg: dict):
    if line.startswith("logging enable"):
        log_cfg["enabled"] = True
    elif line.startswith("logging buffered "):
        log_cfg["buffered_level"] = line.split()[-1]
    elif line.startswith("logging trap "):
        log_cfg["trap_level"] = line.split()[-1]
    elif line.startswith("logging host "):
        log_cfg.setdefault("syslog_servers", []).append(line.split()[2:])
    elif line.startswith("logging timestamp"):
        log_cfg["timestamp"] = True
    elif line.startswith("logging buffer-size"):
        log_cfg["buffer_size"] = line.split()[-1]


def _parse_mgmt_access(line: str, proto: str) -> dict:
    parts = line.split()
    return {
        "protocol": proto,
        "network": parts[1] if len(parts) > 1 else "",
        "mask": parts[2] if len(parts) > 2 else "",
        "interface": parts[3] if len(parts) > 3 else "",
    }


def _parse_snmp_line(line: str, snmp_cfg: dict):
    if "community" in line:
        snmp_cfg.setdefault("communities", []).append(line.split()[-1])
    elif "location" in line:
        snmp_cfg["location"] = line.split(None, 2)[-1]
    elif "contact" in line:
        snmp_cfg["contact"] = line.split(None, 2)[-1]
    elif "enable traps" in line:
        snmp_cfg["traps_enabled"] = True


def _parse_route(line: str) -> dict:
    parts = line.split()
    return {
        "interface": parts[1] if len(parts) > 1 else "",
        "network": parts[2] if len(parts) > 2 else "",
        "mask": parts[3] if len(parts) > 3 else "",
        "gateway": parts[4] if len(parts) > 4 else "",
        "metric": parts[5] if len(parts) > 5 else "",
    }


def _parse_group_policy_attrs(lines: list[str], start: int) -> dict:
    name = lines[start].strip().split()[1]
    gp = {"name": name, "attributes": {}}
    i = start + 1
    while i < len(lines):
        raw = lines[i]
        line = raw.strip()
        if not line or line == "!":
            i += 1
            continue
        if _is_block_end(raw):
            break
        parts = line.split(None, 1)
        if len(parts) == 2:
            gp["attributes"][parts[0]] = parts[1]
        i += 1
    gp["_end_line"] = i
    return gp


def _collect_nat_from_objects(cfg: ParsedConfig):
    value_lookup = {}
    for obj in cfg.objects:
        if obj.get("value"):
            value_lookup[obj["name"]] = obj["value"]

    for obj in cfg.objects:
        if obj.get("nat"):
            resolved_value = obj["value"] or value_lookup.get(obj["name"], "")
            cfg.nat_rules.append({
                "object_name": obj["name"],
                "value": resolved_value,
                "nat_line": obj["nat"],
                "type": "object-nat",
                "is_static_to_outside": "static" in obj["nat"] and "OUTSIDE" in obj["nat"],
            })


# =========================================================================
#  SECURITY ASSESSMENT ENGINE — works with both modes
# =========================================================================

def _assess_config(cfg: ParsedConfig) -> list[dict]:
    findings: list[dict] = []

    _check_acls(cfg, findings)
    _check_nat(cfg, findings)
    _check_crypto(cfg, findings)
    _check_logging(cfg, findings)
    _check_management_access(cfg, findings)
    _check_snmp(cfg, findings)
    _check_ntp(cfg, findings)
    _check_telnet(cfg, findings)
    _check_interfaces(cfg, findings)
    _check_vpn_remote_access(cfg, findings)
    _check_unused_objects(cfg, findings)

    return findings


def _check_acls(cfg: ParsedConfig, findings: list[dict]):
    for acl in cfg.access_lists:
        action = acl.get("action", "")
        raw = acl.get("raw", "")

        if action == "permit" and "any any" in raw:
            findings.append({
                "severity": "HIGH",
                "category": "Access Control",
                "check": "Overly Permissive Rule",
                "target": acl["acl_name"],
                "detail": f"Permits {acl['protocol']} from any to any: {raw}",
            })

        if action == "permit" and "eq 23" in raw:
            findings.append({
                "severity": "HIGH",
                "category": "Access Control",
                "check": "Telnet Permitted in ACL",
                "target": acl["acl_name"],
                "detail": f"Telnet (port 23) allowed: {raw}",
            })

        if action == "permit" and acl["protocol"] == "icmp" and "any any" in raw:
            findings.append({
                "severity": "MEDIUM",
                "category": "Access Control",
                "check": "Unrestricted ICMP",
                "target": acl["acl_name"],
                "detail": f"All ICMP from any to any permitted: {raw}",
            })

        if action == "permit" and acl["protocol"] == "ip":
            src_dest = raw.split("permit ip ", 1)[-1] if "permit ip " in raw else ""
            if "any any" not in raw and "object" in raw:
                parts = src_dest.split()
                if len(parts) >= 2 and parts[0].startswith("object") and parts[1].startswith("object"):
                    findings.append({
                        "severity": "MEDIUM",
                        "category": "Access Control",
                        "check": "All-Ports Access Between Objects",
                        "target": acl["acl_name"],
                        "detail": f"IP (all ports) permitted between objects: {raw}",
                    })


def _check_nat(cfg: ParsedConfig, findings: list[dict]):
    for nat in cfg.nat_rules:
        if nat.get("type") == "object-nat" and nat.get("is_static_to_outside"):
            value = nat.get("value", "")
            if value and not value.startswith("172.16.") and not value.startswith("192.168."):
                is_internal = value.startswith("10.")
                if is_internal:
                    findings.append({
                        "severity": "HIGH",
                        "category": "NAT",
                        "check": "Internal Host Exposed to Outside",
                        "target": nat["object_name"],
                        "detail": f"Internal host {value} has static NAT to OUTSIDE: {nat['nat_line']}",
                    })


def _check_crypto(cfg: ParsedConfig, findings: list[dict]):
    for prop in cfg.crypto_proposals:
        enc = prop.get("encryption", "").lower()
        integ = prop.get("integrity", "").lower()
        if enc in WEAK_ENCRYPTION:
            findings.append({
                "severity": "HIGH",
                "category": "VPN Crypto",
                "check": "Weak Encryption Algorithm",
                "target": f"IPSEC proposal {prop['name']}",
                "detail": f"Uses {enc.upper()} — compromised, use AES-256",
            })
        if integ in WEAK_INTEGRITY:
            findings.append({
                "severity": "HIGH",
                "category": "VPN Crypto",
                "check": "Weak Integrity Algorithm",
                "target": f"IPSEC proposal {prop['name']}",
                "detail": f"Uses {integ.upper()} — collision attacks known, use SHA-256+",
            })

    for pol in cfg.ikev2_policies:
        enc = pol.get("encryption", "").lower()
        integ = pol.get("integrity", "").lower()
        dh = pol.get("dh_group", "")
        if enc in WEAK_ENCRYPTION:
            findings.append({
                "severity": "HIGH",
                "category": "VPN Crypto",
                "check": "Weak IKEv2 Encryption",
                "target": f"IKEv2 policy {pol['priority']}",
                "detail": f"Uses {enc.upper()} — must upgrade to AES-256",
            })
        if integ in WEAK_INTEGRITY:
            findings.append({
                "severity": "HIGH",
                "category": "VPN Crypto",
                "check": "Weak IKEv2 Integrity",
                "target": f"IKEv2 policy {pol['priority']}",
                "detail": f"Uses {integ.upper()} — collision-vulnerable",
            })
        if dh in WEAK_DH_GROUPS:
            findings.append({
                "severity": "HIGH",
                "category": "VPN Crypto",
                "check": "Weak Diffie-Hellman Group",
                "target": f"IKEv2 policy {pol['priority']}",
                "detail": f"DH group {dh} (<=1024-bit) — factorable, use group 19+ (ECDH)",
            })


def _check_logging(cfg: ParsedConfig, findings: list[dict]):
    log = cfg.logging_config
    if not log.get("enabled"):
        findings.append({
            "severity": "HIGH",
            "category": "Logging",
            "check": "Logging Disabled",
            "target": "Global",
            "detail": "No 'logging enable' found",
        })
        return

    level = log.get("buffered_level", "")
    insufficient_levels = {"emergencies", "alerts", "critical", "errors"}
    if level in insufficient_levels:
        findings.append({
            "severity": "MEDIUM",
            "category": "Logging",
            "check": "Insufficient Logging Level",
            "target": "logging buffered",
            "detail": f"Level '{level}' misses warnings and notifications — use 'informational' or 'notifications'",
        })

    if not log.get("syslog_servers"):
        findings.append({
            "severity": "HIGH",
            "category": "Logging",
            "check": "No Syslog Server",
            "target": "Global",
            "detail": "No 'logging host' configured — logs only stored locally, lost on reboot/failure",
        })


def _check_management_access(cfg: ParsedConfig, findings: list[dict]):
    for entry in cfg.ssh_access:
        if entry["network"] == "0.0.0.0" and entry["mask"] == "0.0.0.0":
            findings.append({
                "severity": "HIGH",
                "category": "Management Access",
                "check": "Unrestricted SSH Access",
                "target": f"SSH on {entry['interface']}",
                "detail": f"SSH open to 0.0.0.0/0 on {entry['interface']} — restrict to management subnet",
            })

    for entry in cfg.http_access:
        if entry["network"] == "0.0.0.0" and entry["mask"] == "0.0.0.0":
            findings.append({
                "severity": "HIGH",
                "category": "Management Access",
                "check": "Unrestricted ASDM/HTTP Access",
                "target": f"HTTP on {entry['interface']}",
                "detail": f"ASDM open to 0.0.0.0/0 on {entry['interface']} — restrict to management subnet",
            })


def _check_snmp(cfg: ParsedConfig, findings: list[dict]):
    communities = cfg.snmp_config.get("communities", [])
    default_communities = {"public", "private"}
    for comm in communities:
        if comm.strip('"') in default_communities:
            findings.append({
                "severity": "HIGH",
                "category": "SNMP",
                "check": "Default SNMP Community String",
                "target": f"community '{comm}'",
                "detail": f"Default community '{comm}' — trivially guessable, use SNMPv3 or unique strings",
            })

    if communities and not any(c.strip('"') not in default_communities for c in communities):
        findings.append({
            "severity": "MEDIUM",
            "category": "SNMP",
            "check": "SNMPv2c Only",
            "target": "SNMP config",
            "detail": "Only SNMPv2c community strings found — migrate to SNMPv3 for auth + encryption",
        })


def _check_ntp(cfg: ParsedConfig, findings: list[dict]):
    if cfg.ntp_servers:
        unauthenticated = [s for s in cfg.ntp_servers if not s["authenticated"]]
        if unauthenticated:
            servers = ", ".join(s["server"] for s in unauthenticated)
            findings.append({
                "severity": "MEDIUM",
                "category": "NTP",
                "check": "Unauthenticated NTP",
                "target": servers,
                "detail": "NTP servers configured without authentication — vulnerable to time-spoofing attacks",
            })
    else:
        findings.append({
            "severity": "MEDIUM",
            "category": "NTP",
            "check": "No NTP Configured",
            "target": "Global",
            "detail": "No NTP servers — time drift affects logging, certificates, and VPN",
        })


def _check_telnet(cfg: ParsedConfig, findings: list[dict]):
    if cfg.telnet_access:
        for entry in cfg.telnet_access:
            findings.append({
                "severity": "HIGH",
                "category": "Management Access",
                "check": "Telnet Enabled",
                "target": f"Telnet on {entry['interface']}",
                "detail": f"Telnet from {entry['network']}/{entry['mask']} on {entry['interface']} "
                          f"— cleartext protocol, credentials exposed on wire",
            })


def _check_interfaces(cfg: ParsedConfig, findings: list[dict]):
    for iface in cfg.interfaces:
        if iface["nameif"] and iface["security_level"] == 0 and iface["nameif"] != "OUTSIDE":
            findings.append({
                "severity": "MEDIUM",
                "category": "Interfaces",
                "check": "Security Level 0 on Non-Outside Interface",
                "target": iface["name"],
                "detail": f"Interface {iface['nameif']} has security-level 0 (untrusted)",
            })


def _check_vpn_remote_access(cfg: ParsedConfig, findings: list[dict]):
    gp = cfg.vpn_remote_access.get("group_policy", {})
    attrs = gp.get("attributes", {})

    if gp and "idle-timeout" not in attrs and "vpn-idle-timeout" not in attrs:
        findings.append({
            "severity": "MEDIUM",
            "category": "Remote Access VPN",
            "check": "No VPN Idle Timeout",
            "target": gp.get("name", "group-policy"),
            "detail": "No idle-timeout configured — abandoned sessions remain open indefinitely",
        })


def _check_unused_objects(cfg: ParsedConfig, findings: list[dict]):
    for grp in cfg.object_groups:
        desc = grp.get("description", "").lower()
        if any(kw in desc for kw in ("not in use", "legacy", "deprecated", "old", "unused")):
            findings.append({
                "severity": "LOW",
                "category": "Hygiene",
                "check": "Stale Object Group",
                "target": grp["name"],
                "detail": f"Object group described as '{grp['description']}' — consider removing",
            })


# =========================================================================
#  FMC API ASSESSMENT (original mode)
# =========================================================================

def _assess_fmc(fmc: FMCClient) -> dict:
    findings: list[dict] = []

    devices = fmc.get("devices/devicerecords", {"expanded": "true"}).get("items", [])
    for dev in devices:
        name = dev.get("name", "unknown")
        ver = dev.get("sw_version", "")
        licenses = dev.get("license_caps", [])

        if ver and ver.startswith("6."):
            findings.append({
                "severity": "MEDIUM", "category": "Device Health",
                "check": "Outdated Software", "target": name,
                "detail": f"Running FTD {ver} — version 7.x+ recommended",
            })
        for required in ("IPS", "MALWARE_DEFENSE"):
            if required not in licenses:
                findings.append({
                    "severity": "HIGH", "category": "Licensing",
                    "check": f"Missing {required} License", "target": name,
                    "detail": f"{required} license not present — feature unavailable",
                })

    policies = fmc.get("policy/accesspolicies").get("items", [])
    for pol in policies:
        pol_name = pol["name"]
        rules = fmc.get(
            f"policy/accesspolicies/{pol['id']}/accessrules",
            {"expanded": "true", "limit": 1000},
        ).get("items", [])
        for rule in rules:
            action = rule.get("action", "")
            rule_name = rule.get("name", "Unnamed")
            if action == "ALLOW":
                src = rule.get("sourceNetworks", {}).get("objects", [])
                dst = rule.get("destinationNetworks", {}).get("objects", [])
                if not src or not dst:
                    findings.append({
                        "severity": "HIGH", "category": "Access Policy",
                        "check": "Overly Permissive Rule",
                        "target": f"{pol_name} / {rule_name}",
                        "detail": "ALLOW with unrestricted source or destination",
                    })
                if not rule.get("logBegin") and not rule.get("logEnd"):
                    findings.append({
                        "severity": "MEDIUM", "category": "Access Policy",
                        "check": "Missing Logging",
                        "target": f"{pol_name} / {rule_name}",
                        "detail": "ALLOW rule has no connection logging enabled",
                    })

    ips_policies = fmc.get("policy/intrusionpolicies").get("items", [])
    for ip in ips_policies:
        if ip.get("inspectionMode") == "DETECTION":
            findings.append({
                "severity": "HIGH", "category": "Intrusion Prevention",
                "check": "Detection-Only Mode", "target": ip["name"],
                "detail": "IPS is set to DETECTION — switch to PREVENTION to block threats",
            })

    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "devices_scanned": len(devices),
        "policies_scanned": len(policies),
        "summary": f"{len(high)} HIGH, {len(medium)} MEDIUM findings",
        "high_findings": high,
        "medium_findings": medium,
    }


# =========================================================================
#  MODULE STATE — one of these will be set depending on mode
# =========================================================================

_fmc: FMCClient | None = None
_parsed: ParsedConfig | None = None


def _active_mode() -> str:
    if _parsed:
        return "file"
    if _fmc:
        return "fmc"
    return "none"


# =========================================================================
#  MCP TOOLS
# =========================================================================

@mcp.tool()
def connect_fmc(host: str, username: str, password: str, verify_ssl: bool = False) -> str:
    """
    [LIVE MODE] Authenticate to a Cisco FMC instance.

    Args:
        host:       FMC hostname or IP  (e.g. "10.209.30.1")
        username:   FMC admin username
        password:   FMC admin password
        verify_ssl: Verify TLS certificate (default False for lab/self-signed)
    """
    global _fmc, _parsed
    _parsed = None
    _fmc = FMCClient(host, username, password, verify_ssl=verify_ssl)
    return f"LIVE MODE — Connected to FMC at {host} (domain: {_fmc.domain_uuid})"


@mcp.tool()
def load_config_file(file_path: str) -> str:
    """
    [FILE MODE] Load and parse a 'show run' text config from disk.

    Args:
        file_path: Absolute path to the config file
    """
    global _fmc, _parsed
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {file_path}")
    _fmc = None
    text = path.read_text()
    _parsed = parse_ftd_config(text)
    iface_count = len([i for i in _parsed.interfaces if i["nameif"]])
    acl_count = len(_parsed.access_lists)
    obj_count = len(_parsed.objects)
    return (
        f"FILE MODE — Loaded {path.name}\n"
        f"  Hostname:   {_parsed.hostname}\n"
        f"  Version:    {_parsed.asa_version}\n"
        f"  Serial:     {_parsed.serial_number}\n"
        f"  Interfaces: {iface_count} active\n"
        f"  ACL entries: {acl_count}\n"
        f"  Objects:    {obj_count}"
    )


@mcp.tool()
def get_mode() -> str:
    """Show which mode is active: file, fmc, or none."""
    mode = _active_mode()
    if mode == "file":
        return f"FILE MODE — {_parsed.hostname} ({_parsed.asa_version})"
    if mode == "fmc":
        return f"LIVE MODE — FMC at {_fmc.base_url}"
    return "No data source loaded. Use connect_fmc or load_config_file first."


@mcp.tool()
def list_interfaces() -> list[dict]:
    """List all interfaces with nameif, security-level, IP, and status."""
    if _parsed:
        return [
            {k: v for k, v in iface.items() if k != "_end_line"}
            for iface in _parsed.interfaces
        ]
    if _fmc:
        return _fmc.get("devices/devicerecords", {"expanded": "true"}).get("items", [])
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def list_devices() -> list[dict]:
    """List all FTD devices. In file mode returns parsed device info."""
    if _parsed:
        return [{
            "hostname": _parsed.hostname,
            "version": _parsed.asa_version,
            "serial": _parsed.serial_number,
            "hardware": _parsed.hardware,
            "source": "config file",
        }]
    if _fmc:
        data = _fmc.get("devices/devicerecords", {"expanded": "true"})
        return [
            {
                "name": d.get("name"),
                "sw_version": d.get("sw_version"),
                "model": d.get("model"),
                "health_status": d.get("healthStatus"),
                "licenses": d.get("license_caps", []),
                "hostname": d.get("hostName"),
            }
            for d in data.get("items", [])
        ]
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_access_lists() -> list[dict]:
    """Get all ACL entries. In file mode returns parsed ACLs, in FMC mode returns access policies."""
    if _parsed:
        return [
            {k: v for k, v in acl.items() if k != "_end_line"}
            for acl in _parsed.access_lists
        ]
    if _fmc:
        data = _fmc.get("policy/accesspolicies")
        return [
            {"id": p["id"], "name": p["name"], "description": p.get("description", "")}
            for p in data.get("items", [])
        ]
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_access_rules(policy_id: str = "", limit: int = 1000) -> list[dict]:
    """
    Get access rules. In file mode: returns all ACL rules (policy_id ignored).
    In FMC mode: requires policy_id UUID.

    Args:
        policy_id: Access policy UUID (FMC mode only)
        limit:     Max rules to return
    """
    if _parsed:
        return [
            {k: v for k, v in acl.items() if k != "_end_line"}
            for acl in _parsed.access_lists
        ]
    if _fmc:
        if not policy_id:
            raise ValueError("policy_id required in FMC mode")
        data = _fmc.get(
            f"policy/accesspolicies/{policy_id}/accessrules",
            {"expanded": "true", "limit": limit},
        )
        return data.get("items", [])
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_objects() -> dict:
    """Get all network objects and object groups."""
    if _parsed:
        return {
            "objects": [{k: v for k, v in o.items() if k != "_end_line"} for o in _parsed.objects],
            "object_groups": [{k: v for k, v in g.items() if k != "_end_line"} for g in _parsed.object_groups],
        }
    if _fmc:
        nets = _fmc.get("object/networkobjects", {"expanded": "true", "limit": 1000}).get("items", [])
        grps = _fmc.get("object/networkgroups", {"expanded": "true", "limit": 1000}).get("items", [])
        return {"objects": nets, "object_groups": grps}
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_nat_rules() -> list[dict]:
    """Get all NAT rules."""
    if _parsed:
        return [
            {k: v for k, v in n.items() if k != "_end_line"}
            for n in _parsed.nat_rules
        ]
    if _fmc:
        policies = _fmc.get("policy/ftdnatpolicies").get("items", [])
        all_rules = []
        for pol in policies:
            auto = _fmc.get(f"policy/ftdnatpolicies/{pol['id']}/autonatrules").get("items", [])
            manual = _fmc.get(f"policy/ftdnatpolicies/{pol['id']}/manualnatrules").get("items", [])
            all_rules.extend(auto + manual)
        return all_rules
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_vpn_config() -> dict:
    """Get VPN configuration (crypto proposals, IKEv2 policies, tunnel groups)."""
    if _parsed:
        return {
            "crypto_proposals": [{k: v for k, v in p.items() if k != "_end_line"} for p in _parsed.crypto_proposals],
            "ikev2_policies": [{k: v for k, v in p.items() if k != "_end_line"} for p in _parsed.ikev2_policies],
            "tunnel_groups": [{k: v for k, v in t.items() if k != "_end_line"} for t in _parsed.tunnel_groups],
            "remote_access": _parsed.vpn_remote_access,
        }
    if _fmc:
        s2s = _fmc.get("policy/ftds2svpnpolicies").get("items", [])
        ra = _fmc.get("policy/ftdremoteaccesspolicies").get("items", [])
        return {"site_to_site": s2s, "remote_access": ra}
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_logging_config() -> dict:
    """Get logging configuration (syslog, buffered level, etc.)."""
    if _parsed:
        return _parsed.logging_config
    if _fmc:
        return {"note": "Logging config not available via FMC API — check device CLI"}
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_management_access() -> dict:
    """Get SSH, HTTP/ASDM, and telnet management access settings."""
    if _parsed:
        return {
            "ssh": _parsed.ssh_access,
            "http": _parsed.http_access,
            "telnet": _parsed.telnet_access,
            "users": _parsed.users,
        }
    if _fmc:
        return {"note": "Management access details not available via FMC API — check device CLI"}
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_snmp_config() -> dict:
    """Get SNMP configuration (communities, version, traps)."""
    if _parsed:
        return _parsed.snmp_config
    if _fmc:
        return {"note": "SNMP config not available via FMC API — check device CLI"}
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_routes() -> list[dict]:
    """Get static routes."""
    if _parsed:
        return _parsed.routes
    if _fmc:
        return _fmc.get("devices/devicerecords", {"expanded": "true"}).get("items", [])
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def get_audit_logs(limit: int = 50) -> list[dict]:
    """
    Pull recent audit records. Only available in FMC mode.

    Args:
        limit: How many records to return (default 50)
    """
    if _parsed:
        return [{"note": "Audit logs not available in file mode — requires live FMC connection"}]
    if _fmc:
        return _fmc.get("audit/auditrecords", {"limit": limit}).get("items", [])
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def run_security_assessment() -> dict:
    """
    Run a comprehensive security posture assessment.
    Works in both file mode (parsed config) and FMC mode (live API).
    Returns categorized HIGH, MEDIUM, and LOW findings.
    """
    if _parsed:
        findings = _assess_config(_parsed)
        high = [f for f in findings if f["severity"] == "HIGH"]
        medium = [f for f in findings if f["severity"] == "MEDIUM"]
        low = [f for f in findings if f["severity"] == "LOW"]
        return {
            "mode": "file",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "hostname": _parsed.hostname,
            "version": _parsed.asa_version,
            "summary": f"{len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW findings",
            "high_findings": high,
            "medium_findings": medium,
            "low_findings": low,
        }
    if _fmc:
        return _assess_fmc(_fmc)
    raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")


@mcp.tool()
def generate_report_pdf(output_path: str = "/tmp/ftd_security_report.pdf") -> str:
    """
    Generate a PDF security assessment report. Runs the full assessment
    and writes a formatted PDF to the given path.

    Args:
        output_path: Where to save the PDF (default: /tmp/ftd_security_report.pdf)
    """
    from fpdf import FPDF

    def _safe(text: str) -> str:
        return (text
                .replace("\u2014", "--")
                .replace("\u2013", "-")
                .replace("\u2018", "'")
                .replace("\u2019", "'")
                .replace("\u201c", '"')
                .replace("\u201d", '"')
                .encode("latin-1", errors="replace")
                .decode("latin-1"))

    if not _parsed and not _fmc:
        raise RuntimeError("No data source. Use connect_fmc or load_config_file first.")

    if _parsed:
        findings = _assess_config(_parsed)
        hostname = _parsed.hostname
        version = _parsed.asa_version
        serial = _parsed.serial_number
        mode = "File (show run)"
        iface_count = len([i for i in _parsed.interfaces if i["nameif"]])
        acl_count = len(_parsed.access_lists)
        obj_count = len(_parsed.objects)
    else:
        result = _assess_fmc(_fmc)
        findings = result.get("high_findings", []) + result.get("medium_findings", [])
        hostname = "FMC Managed"
        version = ""
        serial = ""
        mode = f"Live FMC ({_fmc.base_url})"
        iface_count = 0
        acl_count = 0
        obj_count = 0

    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low = [f for f in findings if f["severity"] == "LOW"]
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    DARK = (15, 23, 42)
    WHITE = (255, 255, 255)
    LIGHT_GRAY = (160, 174, 192)
    RED = (239, 68, 68)
    ORANGE = (255, 107, 53)
    YELLOW = (250, 204, 21)
    CYAN = (0, 212, 170)
    BLUE = (0, 158, 247)
    CARD_BG = (26, 35, 59)

    class ReportPDF(FPDF):
        def header(self):
            self.set_fill_color(*DARK)
            self.rect(0, 0, 210, 297, "F")
            self.set_draw_color(*BLUE)
            self.set_line_width(0.8)
            self.line(0, 0, 210, 0)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(*LIGHT_GRAY)
            self.cell(0, 10, f"FTD Security Assessment  |  {hostname}  |  Page {self.page_no()}/{{nb}}", align="C")
            self.set_draw_color(*CYAN)
            self.set_line_width(0.8)
            self.line(0, 297, 210, 297)

    pdf = ReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=20)

    pdf.add_page()
    pdf.set_fill_color(*DARK)
    pdf.rect(0, 0, 210, 297, "F")

    pdf.set_draw_color(*BLUE)
    pdf.set_line_width(1)
    pdf.line(10, 50, 200, 50)
    pdf.set_draw_color(*CYAN)
    pdf.line(10, 52, 200, 52)

    pdf.set_y(65)
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 15, "SECURITY ASSESSMENT", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 18)
    pdf.set_text_color(*CYAN)
    pdf.cell(0, 10, "Cisco FTD / ASA Firewall", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.ln(15)
    pdf.set_draw_color(*CARD_BG)
    pdf.set_fill_color(*CARD_BG)
    pdf.rect(25, pdf.get_y(), 160, 55, "F")

    info_y = pdf.get_y() + 5
    pdf.set_y(info_y)
    info_items = [
        ("Hostname:", hostname),
        ("Version:", version),
        ("Serial:", serial),
        ("Source:", mode),
        ("Generated:", timestamp),
    ]
    for label, value in info_items:
        pdf.set_x(35)
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*LIGHT_GRAY)
        pdf.cell(35, 8, label)
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(*WHITE)
        pdf.cell(0, 8, _safe(str(value)), new_x="LMARGIN", new_y="NEXT")

    pdf.ln(15)

    box_w = 50
    box_h = 25
    start_x = (210 - box_w * 3 - 10) / 2
    box_y = pdf.get_y()

    for i, (label, count, color) in enumerate([("HIGH", len(high), RED), ("MEDIUM", len(medium), ORANGE), ("LOW", len(low), YELLOW)]):
        bx = start_x + i * (box_w + 5)
        pdf.set_fill_color(*color)
        pdf.rect(bx, box_y, box_w, box_h, "F")
        pdf.set_xy(bx, box_y + 2)
        pdf.set_font("Helvetica", "B", 22)
        pdf.set_text_color(*DARK)
        pdf.cell(box_w, 12, str(count), align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.set_xy(bx, box_y + 14)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(box_w, 8, label, align="C")

    pdf.ln(box_h + 10)
    pdf.set_font("Helvetica", "I", 10)
    pdf.set_text_color(*LIGHT_GRAY)
    pdf.cell(0, 8, "Assessment based on CIS Benchmarks, Cisco hardening guides, and NIST SP 800-41", align="C")

    def add_findings_section(severity_label, items, badge_color):
        if not items:
            return
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(*badge_color)
        pdf.cell(0, 12, f"{severity_label} FINDINGS ({len(items)})", new_x="LMARGIN", new_y="NEXT")

        pdf.set_draw_color(*badge_color)
        pdf.set_line_width(0.6)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)

        for idx, f in enumerate(items, 1):
            space_needed = 35
            if pdf.get_y() + space_needed > 275:
                pdf.add_page()

            card_y = pdf.get_y()
            pdf.set_fill_color(*CARD_BG)
            pdf.rect(10, card_y, 190, 30, "F")

            pdf.set_fill_color(*badge_color)
            pdf.rect(10, card_y, 3, 30, "F")

            pdf.set_xy(16, card_y + 2)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*badge_color)
            pdf.cell(15, 6, f"#{idx}")
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*WHITE)
            pdf.cell(80, 6, _safe(f["check"]))
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*LIGHT_GRAY)
            pdf.cell(0, 6, _safe(f"[{f['category']}]"), align="R", new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(16)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*CYAN)
            pdf.cell(15, 5, "Target:")
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*WHITE)
            pdf.cell(0, 5, _safe(f["target"]), new_x="LMARGIN", new_y="NEXT")

            pdf.set_x(16)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(*LIGHT_GRAY)
            detail = f["detail"]
            if len(detail) > 120:
                detail = detail[:117] + "..."
            pdf.cell(180, 5, _safe(detail), new_x="LMARGIN", new_y="NEXT")

            pdf.ln(4)

    add_findings_section("HIGH", high, RED)
    add_findings_section("MEDIUM", medium, ORANGE)
    add_findings_section("LOW", low, YELLOW)

    if _parsed:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(*BLUE)
        pdf.cell(0, 12, "CONFIGURATION SUMMARY", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(*BLUE)
        pdf.set_line_width(0.6)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(8)

        summary_items = [
            ("Active Interfaces", str(iface_count)),
            ("ACL Entries", str(acl_count)),
            ("Network Objects", str(obj_count)),
            ("NAT Rules", str(len(_parsed.nat_rules))),
            ("IPSEC Proposals", str(len(_parsed.crypto_proposals))),
            ("IKEv2 Policies", str(len(_parsed.ikev2_policies))),
            ("Tunnel Groups", str(len(_parsed.tunnel_groups))),
            ("Static Routes", str(len(_parsed.routes))),
            ("Syslog Servers", str(len(_parsed.logging_config.get("syslog_servers", [])))),
            ("NTP Servers", str(len(_parsed.ntp_servers))),
            ("Local Users", str(len(_parsed.users))),
        ]

        for label, value in summary_items:
            pdf.set_fill_color(*CARD_BG)
            row_y = pdf.get_y()
            pdf.rect(10, row_y, 190, 8, "F")
            pdf.set_x(15)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(*LIGHT_GRAY)
            pdf.cell(80, 8, label)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(*WHITE)
            pdf.cell(0, 8, value, new_x="LMARGIN", new_y="NEXT")
            pdf.ln(1)

    pdf.output(output_path)
    total = len(high) + len(medium) + len(low)
    return f"PDF report saved to {output_path} ({total} findings: {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW)"


if __name__ == "__main__":
    mcp.run(transport="stdio")
