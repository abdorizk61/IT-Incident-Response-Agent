"""
tools.py - IT Infrastructure and Diagnostic Domain Tools
Provides robust domain tools wrapped with the `openai-agents` `@function_tool` decorator.
Implements in-memory mock data, tool-level safety guardrails, and graceful error handling.
"""

from datetime import datetime, timezone
import re
import threading
from typing import Any, Callable, Dict, List, Optional
from agents import function_tool, FunctionTool


# ============================================================================
# TOOL-LEVEL SAFETY GUARDRAIL
# ============================================================================

# Patterns representing unauthorized administrative, destructive, or malicious command injections
DISALLOWED_TOOL_PATTERNS = [
    r"(?:^|[;&|\n`])\s*(?:sudo\s+)?rm\s+-rf\b",
    r"(?:^|[;&|\n`])\s*format\s+[a-z]:\b",
    r"(?:^|[;&|\n`])\s*(?:sudo\s+)?mkfs\b",
    r"(?:^|[;&|\n`])\s*(?:sudo\s+)?(?:shutdown|reboot|poweroff)\b",
    r"\bdrop\s+(?:table|database|schema)\b",
    r"\btruncate\s+(?:table)?\b",
    r"(?:^|[;&|\n`])\s*sudo\s+(?:su|bash|sh|chmod|chown)\b",
    r"(?:^|[;&|\n`])\s*chmod\s+777\b",
    r"cat\s+/etc/shadow\b",
    r"\bmimikatz\b",
    r"\bpwndbg\b",
    r"\bpowershell.*-enc\b",
    r"\bgrant_admin\b",
    r"\belevate_privileges\b",
    r"\bdisable_edr\b",
    r"\bstop_antivirus\b",
    r"\bunion\s+select\b",
    r"\bor\s+['\"]1['\"]\s*=\s*['\"]1\b",
]

TOOL_SECURITY_LOGS: List[Dict[str, Any]] = []
_SECURITY_LOGS_LOCK = threading.Lock()


def check_tool_input_safety(tool_name: str, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """
    Enforces the tool-level safety guardrail:
    Blocks unauthorized administrative commands, destructive SQL, or malicious exploits.
    Returns an error dictionary if a violation is detected, otherwise None.
    """
    for param_name, param_value in kwargs.items():
        if isinstance(param_value, str):
            for pattern in DISALLOWED_TOOL_PATTERNS:
                if re.search(pattern, param_value, re.IGNORECASE):
                    incident_info = {
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "tool": tool_name,
                        "blocked_parameter": param_name,
                        "flagged_payload": param_value,
                        "pattern_matched": pattern,
                        "action": "BLOCKED_BY_TOOL_GUARDRAIL",
                    }
                    with _SECURITY_LOGS_LOCK:
                        TOOL_SECURITY_LOGS.append(incident_info)
                    return {
                        "status": "BLOCKED_BY_TOOL_GUARDRAIL",
                        "error": (
                            f"Tool-level safety guardrail blocked unauthorized administrative command payload "
                            f"in parameter '{param_name}': detected forbidden pattern '{pattern}'."
                        ),
                        "violation_type": "UNAUTHORIZED_ADMIN_COMMAND",
                        "security_incident_logged": True,
                    }
    return None


# ============================================================================
# IN-MEMORY MOCK DATABASES
# ============================================================================

ACCOUNTS_DB: Dict[str, Dict[str, Any]] = {
    "usr_alice": {
        "user_id": "usr_alice",
        "name": "Alice Chen",
        "email": "alice@corp.internal",
        "department": "Engineering",
        "account_status": "LOCKED",
        "mfa_failed_attempts": 5,
        "password_expired": False,
        "last_login": "2026-10-15T08:12:00Z",
        "assigned_device": "dev_mac_101",
        "lock_reason": "Exceeded 5 consecutive MFA push rejections/timeouts",
        "roles": ["eng-developer", "code-reviewer"],
    },
    "usr_bob": {
        "user_id": "usr_bob",
        "name": "Bob Miller",
        "email": "bob@corp.internal",
        "department": "Finance",
        "account_status": "ACTIVE",
        "mfa_failed_attempts": 0,
        "password_expired": False,
        "last_login": "2026-10-15T07:45:00Z",
        "assigned_device": "dev_pc_404",
        "lock_reason": None,
        "roles": ["finance-analyst", "erp-user"],
    },
    "usr_charlie": {
        "user_id": "usr_charlie",
        "name": "Charlie Davis",
        "email": "charlie@corp.internal",
        "department": "Marketing",
        "account_status": "ACTIVE",
        "mfa_failed_attempts": 0,
        "password_expired": False,
        "last_login": "2026-10-15T09:00:00Z",
        "assigned_device": "dev_mac_101",
        "lock_reason": None,
        "roles": ["marketing-lead"],
    },
    "usr_devon": {
        "user_id": "usr_devon",
        "name": "Devon Vance",
        "email": "devon@corp.internal",
        "department": "Operations",
        "account_status": "SUSPENDED_SECURITY",
        "mfa_failed_attempts": 0,
        "password_expired": False,
        "last_login": "2026-10-15T03:22:11Z",
        "assigned_device": "dev_win_202",
        "lock_reason": "Active malware & ransomware containment on host dev_win_202",
        "roles": ["ops-technician"],
    },
    "usr_eva": {
        "user_id": "usr_eva",
        "name": "Eva Rostova",
        "email": "eva@corp.internal",
        "department": "Legal",
        "account_status": "EXPIRED_CREDENTIALS",
        "mfa_failed_attempts": 2,
        "password_expired": True,
        "last_login": "2026-09-30T17:00:00Z",
        "assigned_device": "dev_pc_404",
        "lock_reason": "90-day password rotation deadline lapsed without renewal",
        "roles": ["legal-counsel"],
    },
}

VPN_SESSIONS_DB: Dict[str, Dict[str, Any]] = {
    "usr_alice": {
        "user_id": "usr_alice",
        "vpn_state": "DISCONNECTED",
        "last_attempt": "2026-10-15T08:15:00Z",
        "gateway": "vpn-ny-01.corp.internal",
        "client_cert_status": "VALID",
        "cert_expiry_date": "2027-01-15T00:00:00Z",
        "error_message": "Authentication rejected by directory service (User account usr_alice is LOCKED).",
    },
    "usr_bob": {
        "user_id": "usr_bob",
        "vpn_state": "AUTH_FAILED",
        "last_attempt": "2026-10-15T07:45:00Z",
        "gateway": "vpn-ny-01.corp.internal",
        "client_cert_status": "EXPIRED",
        "cert_expiry_date": "2026-10-14T00:00:00Z",
        "error_message": "TLS Handshake Failed: Client Certificate Expired on 2026-10-14T00:00:00Z (CERT_HAS_EXPIRED).",
    },
    "usr_charlie": {
        "user_id": "usr_charlie",
        "vpn_state": "CONNECTED",
        "last_attempt": "2026-10-15T09:05:00Z",
        "gateway": "vpn-sf-02.corp.internal",
        "assigned_ip": "10.200.14.88",
        "client_cert_status": "VALID",
        "latency_ms": 19,
        "packet_loss_pct": 0.0,
        "error_message": None,
    },
    "usr_devon": {
        "user_id": "usr_devon",
        "vpn_state": "FLAGGED_ANOMALOUS",
        "last_attempt": "2026-10-15T03:22:11Z",
        "gateway": "vpn-ny-01.corp.internal",
        "assigned_ip": "185.220.101.5",
        "client_cert_status": "VALID",
        "geo_location": "Tor Exit Node / Foreign Autonomous System",
        "error_message": "Impossible travel detection alert: Session initiated from external foreign IP within 15 min of local badge login.",
    },
}

DEVICES_DB: Dict[str, Dict[str, Any]] = {
    "dev_mac_101": {
        "device_id": "dev_mac_101",
        "hostname": "MBP-Alice-101",
        "model": "Apple MacBook Pro 16-inch M3",
        "os_version": "macOS Sonoma 14.7",
        "mdm_status": "NON_COMPLIANT",
        "filevault_encryption": "DISABLED",
        "edr_agent_status": "RUNNING (Falcon 7.18)",
        "cpu_load_pct": 94.2,
        "memory_used_pct": 89.1,
        "disk_free_gb": 14.2,
        "runaway_processes": ["photo_sync_indexer (PID 4821, CPU 86%)", "legacy_spotlight_rebuild (PID 5102, CPU 12%)"],
        "compliance_violations": [
            "FileVault disk encryption is DISABLED (Policy SEC-MDM-04)",
            "Required OS update macOS 15.1 pending for >14 days",
        ],
    },
    "dev_win_202": {
        "device_id": "dev_win_202",
        "hostname": "WIN-Devon-202",
        "model": "Dell Latitude 5540",
        "os_version": "Windows 11 Enterprise 23H2",
        "mdm_status": "ISOLATED_QUARANTINE",
        "bitlocker_encryption": "ENABLED",
        "edr_agent_status": "CRITICAL_ALERT (Falcon 7.18)",
        "cpu_load_pct": 98.0,
        "memory_used_pct": 95.0,
        "disk_free_gb": 4.1,
        "threat_detection": "Ransomware behavioral heuristic: Rapid renaming of user documents to .locked extension with ransom note README_DECRYPT.txt. Host isolated from local network by EDR.",
    },
    "dev_linux_303": {
        "device_id": "dev_linux_303",
        "hostname": "SRV-Linux-303",
        "model": "Dell PowerEdge R650 Server",
        "os_version": "Ubuntu 24.04 LTS",
        "mdm_status": "DEGRADED",
        "edr_agent_status": "RUNNING",
        "cpu_load_pct": 14.0,
        "memory_used_pct": 42.0,
        "uptime": "114 days",
        "hardware_diagnostics": "Machine Check Exception (MCE): Uncorrectable multi-bit ECC memory error reported by CPU Bank 3. Recurring kernel panics detected.",
    },
    "dev_pc_404": {
        "device_id": "dev_pc_404",
        "hostname": "PC-Bob-404",
        "model": "HP EliteBook 840 G10",
        "os_version": "Windows 11 Pro 23H2",
        "mdm_status": "COMPLIANT",
        "bitlocker_encryption": "ENABLED",
        "edr_agent_status": "HEALTHY",
        "cpu_load_pct": 18.5,
        "memory_used_pct": 45.0,
        "disk_free_gb": 220.0,
        "runaway_processes": [],
    },
}

NETWORKS_DB: Dict[str, Dict[str, Any]] = {
    "10.0.4.1": {
        "location_or_ip": "10.0.4.1",
        "facility": "US-East-Branch Office (HQ-Floor2)",
        "network_status": "CRITICAL_OUTAGE",
        "ping_latency": "TIMEOUT",
        "packet_loss_pct": 100.0,
        "dns_resolution": "FAILED",
        "gateway_interface": "GigabitEthernet0/0/1 (DOWN)",
        "upstream_isp": "Lumen Enterprise Fiber",
        "circuit_id": "LUM-FIB-90218",
        "telemetry_note": "Upstream fiber carrier reports regional physical cut on metro ring. ETA for repair: 3 hours.",
    },
    "HQ-Floor2": {
        "location_or_ip": "HQ-Floor2",
        "facility": "Corporate HQ - 2nd Floor Access Layer",
        "network_status": "CRITICAL_OUTAGE",
        "ping_latency": "TIMEOUT",
        "packet_loss_pct": 100.0,
        "dns_resolution": "FAILED",
        "gateway_interface": "GigabitEthernet0/0/1 (DOWN)",
        "upstream_isp": "Lumen Enterprise Fiber",
        "circuit_id": "LUM-FIB-90218",
        "telemetry_note": "Gateway 10.0.4.1 is completely unreachable. 100% packet loss to all clients on Floor 2.",
    },
    "US-East-Branch": {
        "location_or_ip": "US-East-Branch",
        "facility": "US-East Branch Regional Gateway",
        "network_status": "CRITICAL_OUTAGE",
        "ping_latency": "TIMEOUT",
        "packet_loss_pct": 100.0,
        "dns_resolution": "FAILED",
        "gateway_interface": "GigabitEthernet0/0/1 (DOWN)",
        "upstream_isp": "Lumen Enterprise Fiber",
        "circuit_id": "LUM-FIB-90218",
        "telemetry_note": "Regional WAN fiber severed. Secondary failover LTE link failed handshake.",
    },
    "192.168.1.50": {
        "location_or_ip": "192.168.1.50",
        "facility": "Corporate Campus Core Switch",
        "network_status": "HEALTHY",
        "ping_latency": "2.1ms",
        "packet_loss_pct": 0.0,
        "dns_resolution": "HEALTHY (10.0.0.2 / 8.8.8.8)",
        "gateway_interface": "TenGigabitEthernet1/1/1 (UP)",
        "bandwidth_utilization_pct": 32.4,
        "telemetry_note": "All core routing protocols operational. BGP and OSPF adjacencies stable.",
    },
    "10.0.2.1": {
        "location_or_ip": "10.0.2.1",
        "facility": "Remote Access Concentrator Cluster",
        "network_status": "DEGRADED",
        "ping_latency": "142ms",
        "packet_loss_pct": 12.5,
        "dns_resolution": "HEALTHY",
        "gateway_interface": "Cluster VIP (UP)",
        "bandwidth_utilization_pct": 98.2,
        "active_vpn_tunnels": 2490,
        "max_capacity": 2500,
        "telemetry_note": "VPN gateway cluster approaching maximum concurrency limit. Buffer queue saturation causing jitter.",
    },
}

IT_KNOWLEDGE_BASE: List[Dict[str, Any]] = [
    {
        "kb_id": "KB-101",
        "title": "Account Lockout & MFA Reset Standard Operating Procedure",
        "category": "Account",
        "tags": ["lockout", "mfa", "password", "active directory", "okta"],
        "content": (
            "1. Verify employee identity via manager confirmation or secure SMS.\n"
            "2. In Okta / Active Directory admin console, locate user account.\n"
            "3. If lockout occurred due to >5 failed MFA pushes, inspect sign-in logs for foreign IP.\n"
            "4. If no suspicious geo-location: Click 'Unlock Account' and trigger MFA token resync.\n"
            "5. Advise user to restart browser session and clear stale SSO cookies."
        ),
    },
    {
        "kb_id": "KB-102",
        "title": "VPN Client Certificate Expiration & Renewal Protocol",
        "category": "Network",
        "tags": ["vpn", "certificate", "tls", "globalprotect", "pki"],
        "content": (
            "1. When VPN handshake fails with CERT_HAS_EXPIRED, the machine certificate on the endpoint has expired.\n"
            "2. User must navigate to the internal cert renewal portal: https://certs.corp.internal/selfservice.\n"
            "3. If offsite without VPN, user must use the captive web portal with WebAuth to request new cert.\n"
            "4. Download and install 'Corp-Device-2026.p12' into Keychain (macOS) or CertMgr (Windows).\n"
            "5. Restart GlobalProtect / AnyConnect client and select newly imported certificate."
        ),
    },
    {
        "kb_id": "KB-103",
        "title": "Ransomware & Active Intrusion Incident Response Runbook",
        "category": "Security",
        "tags": ["ransomware", "malware", "compromise", "soc", "isolation"],
        "content": (
            "CRITICAL PROTOCOL - FORBID AUTONOMOUS CLOSURE:\n"
            "1. Immediately isolate affected host from all physical and wireless networks.\n"
            "2. Instruct employee NOT to reboot machine (preserve RAM for forensic triage).\n"
            "3. Revoke all active SSO/Kerberos tickets and suspend Active Directory user account.\n"
            "4. Create P1 Security Incident ticket and page the on-call Security Operations Center (SOC).\n"
            "5. Collect EDR memory dump, hash artifacts, and preserve backup snapshots."
        ),
    },
    {
        "kb_id": "KB-104",
        "title": "MDM Non-Compliance, FileVault & Patch Remediation Runbook",
        "category": "Device",
        "tags": ["mdm", "jamf", "intune", "filevault", "bitlocker", "patch"],
        "content": (
            "1. When endpoint status is NON_COMPLIANT due to FileVault/BitLocker disabled:\n"
            "2. On macOS: System Settings -> Privacy & Security -> FileVault -> Turn On.\n"
            "3. Ensure Institutional Recovery Key (IRK) escrow is uploaded to Jamf Pro.\n"
            "4. Install mandatory pending OS patches and reboot.\n"
            "5. Run 'sudo jamf recon' or Intune Sync to refresh device compliance inventory."
        ),
    },
    {
        "kb_id": "KB-105",
        "title": "High CPU & Runaway Background Process Troubleshooting",
        "category": "Device",
        "tags": ["cpu", "performance", "photo_sync", "spotlight", "indexing"],
        "content": (
            "1. Inspect Task Manager or Activity Monitor for processes consuming >80% CPU.\n"
            "2. Common rogue process 'photo_sync_indexer' or 'mds_stores' can be killed via terminal.\n"
            "3. macOS command: 'kill -9 <PID>' or pause background photo sync in iCloud settings.\n"
            "4. Verify free disk space: system requires at least 20GB free for virtual memory swap.\n"
            "5. Clean cache directories: ~/Library/Caches and reboot."
        ),
    },
    {
        "kb_id": "KB-106",
        "title": "Branch Office WAN Gateway & ISP Fiber Outage SOP",
        "category": "Network",
        "tags": ["network", "wan", "isp", "fiber", "switch", "100% packet loss"],
        "content": (
            "1. For 100% packet loss at branch office (e.g. 10.0.4.1 / HQ-Floor2):\n"
            "2. Check edge router physical interface lights and upstream fiber optical levels.\n"
            "3. If interface is DOWN, contact carrier ISP with circuit identifier (e.g. LUM-FIB-90218).\n"
            "4. Escalate to Network Engineering P1 queue immediately.\n"
            "5. Switch branch traffic to backup Cellular/LTE failover gateway if available."
        ),
    },
    {
        "kb_id": "KB-107",
        "title": "Hardware Machine Check Exception (MCE) & Memory Corruption SOP",
        "category": "Device",
        "tags": ["hardware", "memory", "ecc", "kernel panic", "server"],
        "content": (
            "1. Repeated kernel panics with MCE / ECC uncorrectable error indicate failing physical RAM DIMM.\n"
            "2. Autonomous software remediation is NOT possible for hardware component failure.\n"
            "3. Drain server workloads and migrate virtual machines to healthy cluster nodes.\n"
            "4. File critical hardware replacement ticket with Dell/HP vendor support.\n"
            "5. Dispatch on-site technician to replace flagged memory module in Bank 3."
        ),
    },
]

IT_TICKETS_DB: List[Dict[str, Any]] = []
_TICKETS_LOCK = threading.Lock()


# ============================================================================
# CALLABLE FUNCTION TOOL WRAPPER
# ============================================================================

class CallableFunctionTool(FunctionTool):
    """
    Subclass of FunctionTool that allows direct Python invocation `tool(*args, **kwargs)`
    while remaining completely compatible with openai-agents `Agent(tools=[...])`.
    """
    _callable: Any = None

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        if self._callable is None:
            raise TypeError(f"Tool {self.name} has no underlying callable assigned.")
        return self._callable(*args, **kwargs)


def make_callable_tool(fn: Callable[..., Any]) -> CallableFunctionTool:
    """Helper decorator to build a FunctionTool that is also directly callable in Python."""
    base_tool = function_tool(fn)
    fields = {k: getattr(base_tool, k) for k in base_tool.__dataclass_fields__}
    c_tool = CallableFunctionTool(**fields)
    c_tool._callable = fn
    return c_tool


# ============================================================================
# DOMAIN TOOLS
# ============================================================================

def _raw_check_account_status(user_id: str) -> Dict[str, Any]:
    """Inspect user identity, account lockout, MFA state, and directory roles."""
    safety_violation = check_tool_input_safety("check_account_status", user_id=user_id)
    if safety_violation:
        return safety_violation

    user_clean = user_id.strip().lower()
    if user_clean in ACCOUNTS_DB:
        acc = dict(ACCOUNTS_DB[user_clean])
        return {
            "status": "SUCCESS",
            "found": True,
            "account": acc,
            "evidence": (
                f"User: {acc['name']} ({acc['user_id']}) | Department: {acc['department']} | "
                f"Status: {acc['account_status']} | MFA Failures: {acc['mfa_failed_attempts']} | "
                f"Lock Reason: {acc['lock_reason']}"
            ),
        }
    return {
        "status": "SUCCESS",
        "found": False,
        "user_id": user_id,
        "account": {"user_id": user_id, "account_status": "UNKNOWN_USER"},
        "evidence": f"User ID '{user_id}' was not found in directory services.",
    }


@make_callable_tool
def check_account_status(user_id: str) -> Dict[str, Any]:
    """
    Inspect user identity, account lockout, MFA state, and directory roles.

    Args:
        user_id: Unique user identifier (e.g. 'usr_alice', 'usr_bob').

    Returns:
        Dictionary containing account status, MFA attempts, and evidence string.
    """
    try:
        return _raw_check_account_status(user_id)
    except Exception as e:
        return {"status": "ERROR", "error": f"Failed checking account for {user_id}: {str(e)}"}


def _raw_check_vpn_status(user_id: str) -> Dict[str, Any]:
    """Inspect active VPN sessions, client TLS certificate validity, and connection gateways."""
    safety_violation = check_tool_input_safety("check_vpn_status", user_id=user_id)
    if safety_violation:
        return safety_violation

    user_clean = user_id.strip().lower()
    if user_clean in VPN_SESSIONS_DB:
        vpn = dict(VPN_SESSIONS_DB[user_clean])
        return {
            "status": "SUCCESS",
            "found": True,
            "vpn_session": vpn,
            "evidence": (
                f"VPN Status for {vpn['user_id']}: State={vpn['vpn_state']} | "
                f"Cert Status={vpn.get('client_cert_status', 'N/A')} | "
                f"Gateway={vpn.get('gateway', 'N/A')} | Error={vpn.get('error_message', 'None')}"
            ),
        }
    return {
        "status": "SUCCESS",
        "found": False,
        "user_id": user_id,
        "vpn_session": {"vpn_state": "NO_RECORD_FOUND"},
        "evidence": f"No active or recent VPN session found for user '{user_id}'.",
    }


@make_callable_tool
def check_vpn_status(user_id: str) -> Dict[str, Any]:
    """
    Inspect active VPN sessions, client TLS certificate validity, and connection gateways.

    Args:
        user_id: Unique user identifier (e.g. 'usr_alice', 'usr_bob').

    Returns:
        Dictionary containing VPN connectivity metrics, TLS cert status, and telemetry.
    """
    try:
        return _raw_check_vpn_status(user_id)
    except Exception as e:
        return {"status": "ERROR", "error": f"Failed checking VPN status for {user_id}: {str(e)}"}


def _raw_check_device_status(device_id: str) -> Dict[str, Any]:
    """Inspect MDM compliance, OS version, disk encryption, EDR alerts, and CPU/memory telemetry."""
    safety_violation = check_tool_input_safety("check_device_status", device_id=device_id)
    if safety_violation:
        return safety_violation

    dev_clean = device_id.strip().lower()
    if dev_clean in DEVICES_DB:
        dev = dict(DEVICES_DB[dev_clean])
        evidence_parts = [
            f"Device: {dev.get('hostname', dev['device_id'])} ({dev['device_id']})",
            f"Model: {dev.get('model', 'N/A')}",
            f"MDM Compliance: {dev.get('mdm_status', 'UNKNOWN')}",
            f"CPU Load: {dev.get('cpu_load_pct', 0)}%",
            f"EDR Status: {dev.get('edr_agent_status', 'HEALTHY')}",
        ]
        if "threat_detection" in dev:
            evidence_parts.append(f"THREAT: {dev['threat_detection']}")
        if "hardware_diagnostics" in dev:
            evidence_parts.append(f"HARDWARE: {dev['hardware_diagnostics']}")
        if dev.get("runaway_processes"):
            evidence_parts.append(f"Runaway Processes: {', '.join(dev['runaway_processes'])}")

        return {
            "status": "SUCCESS",
            "found": True,
            "device": dev,
            "evidence": " | ".join(evidence_parts),
        }
    return {
        "status": "SUCCESS",
        "found": False,
        "device_id": device_id,
        "device": {"device_id": device_id, "mdm_status": "DEVICE_NOT_FOUND"},
        "evidence": f"Device ID '{device_id}' was not found in MDM inventory.",
    }


@make_callable_tool
def check_device_status(device_id: str) -> Dict[str, Any]:
    """
    Inspect MDM compliance, OS version, disk encryption, EDR alerts, and CPU/memory telemetry.

    Args:
        device_id: Hardware or endpoint identifier (e.g. 'dev_mac_101', 'dev_win_202').

    Returns:
        Dictionary containing endpoint compliance, running processes, and security alerts.
    """
    try:
        return _raw_check_device_status(device_id)
    except Exception as e:
        return {"status": "ERROR", "error": f"Failed checking device {device_id}: {str(e)}"}


def _raw_check_network_status(location_or_ip: str) -> Dict[str, Any]:
    """Inspect network switch, gateway ping latency, packet loss, DNS resolution, and ISP health."""
    safety_violation = check_tool_input_safety("check_network_status", location_or_ip=location_or_ip)
    if safety_violation:
        return safety_violation

    target = location_or_ip.strip()
    # Direct match or partial match
    matched_entry = None
    if target in NETWORKS_DB:
        matched_entry = dict(NETWORKS_DB[target])
    else:
        for key, val in NETWORKS_DB.items():
            if target.lower() in key.lower() or target.lower() in val.get("facility", "").lower():
                matched_entry = dict(val)
                break

    if matched_entry:
        return {
            "status": "SUCCESS",
            "found": True,
            "network": matched_entry,
            "evidence": (
                f"Network Target: {matched_entry.get('facility', target)} | "
                f"Status: {matched_entry.get('network_status', 'UNKNOWN')} | "
                f"Packet Loss: {matched_entry.get('packet_loss_pct', 0)}% | "
                f"Ping Latency: {matched_entry.get('ping_latency', 'N/A')} | "
                f"Telemetry: {matched_entry.get('telemetry_note', 'None')}"
            ),
        }

    return {
        "status": "SUCCESS",
        "found": False,
        "location_or_ip": location_or_ip,
        "network": {"network_status": "UNREACHABLE_OR_UNKNOWN"},
        "evidence": f"Network target '{location_or_ip}' does not match any known gateway, IP, or facility.",
    }


@make_callable_tool
def check_network_status(location_or_ip: str) -> Dict[str, Any]:
    """
    Inspect network switch, gateway ping latency, packet loss, DNS resolution, and ISP health.

    Args:
        location_or_ip: IP address, gateway hostname, or office location (e.g. '10.0.4.1', 'HQ-Floor2').

    Returns:
        Dictionary containing network diagnostic state, packet loss, and circuit metrics.
    """
    try:
        return _raw_check_network_status(location_or_ip)
    except Exception as e:
        return {"status": "ERROR", "error": f"Failed checking network for {location_or_ip}: {str(e)}"}


def _raw_search_it_knowledge(query: str) -> Dict[str, Any]:
    """Search internal IT Knowledge Base runbooks and Standard Operating Procedures (SOPs)."""
    safety_violation = check_tool_input_safety("search_it_knowledge", query=query)
    if safety_violation:
        return safety_violation

    query_tokens = set(re.findall(r"\w+", query.lower()))
    matches = []

    for kb in IT_KNOWLEDGE_BASE:
        score = 0
        text_corpus = f"{kb['title']} {kb['category']} {' '.join(kb['tags'])} {kb['content']}".lower()
        for token in query_tokens:
            if token in text_corpus:
                score += 1
        if score > 0:
            matches.append((score, kb))

    matches.sort(key=lambda x: x[0], reverse=True)
    results = [m[1] for m in matches[:3]]

    if not results and IT_KNOWLEDGE_BASE:
        # Fallback to top general article if query was ambiguous
        results = [IT_KNOWLEDGE_BASE[0]]

    evidence_summary = "\n---\n".join(
        [f"[{r['kb_id']}] {r['title']}:\n{r['content']}" for r in results]
    )

    return {
        "status": "SUCCESS",
        "query": query,
        "match_count": len(results),
        "articles": results,
        "evidence": evidence_summary,
    }


@make_callable_tool
def search_it_knowledge(query: str) -> Dict[str, Any]:
    """
    Search internal IT Knowledge Base runbooks and Standard Operating Procedures (SOPs).

    Args:
        query: Keywords or description of the issue to retrieve SOPs for.

    Returns:
        Dictionary containing matched runbooks, procedure steps, and guidelines.
    """
    try:
        return _raw_search_it_knowledge(query)
    except Exception as e:
        return {"status": "ERROR", "error": f"Failed searching knowledge base: {str(e)}"}


def _raw_create_it_ticket(title: str, priority: str, details: str) -> Dict[str, Any]:
    """Create an official IT Service Management (ITSM) incident ticket."""
    safety_violation = check_tool_input_safety("create_it_ticket", title=title, priority=priority, details=details)
    if safety_violation:
        return safety_violation

    clean_priority = priority.capitalize()
    if clean_priority not in ["Low", "Medium", "High", "Critical"]:
        clean_priority = "Medium"

    ticket_num = len(IT_TICKETS_DB) + 1001
    ticket_id = f"TICK-{ticket_num}"

    # Determine assigned escalation queue
    assigned_team = "L1-Helpdesk"
    details_lower = f"{title} {details}".lower()
    if "ransomware" in details_lower or "malware" in details_lower or "security" in details_lower:
        assigned_team = "SOC-Tier1-Escalations"
    elif "fiber" in details_lower or "packet loss" in details_lower or "gateway" in details_lower or "network" in details_lower:
        assigned_team = "Network-Ops-Engineering"
    elif "hardware" in details_lower or "ecc" in details_lower or "kernel panic" in details_lower:
        assigned_team = "L3-Systems-Engineering"
    elif clean_priority == "Critical":
        assigned_team = "Major-Incident-Management"

    ticket_record = {
        "ticket_id": ticket_id,
        "title": title,
        "priority": clean_priority,
        "status": "OPEN_ASSIGNED",
        "assigned_team": assigned_team,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }

    with _TICKETS_LOCK:
        IT_TICKETS_DB.append(ticket_record)

    return {
        "status": "SUCCESS",
        "ticket_id": ticket_id,
        "assigned_team": assigned_team,
        "priority": clean_priority,
        "evidence": (
            f"Created ITSM Ticket {ticket_id} with priority '{clean_priority}' assigned to "
            f"team '{assigned_team}'. Title: {title}"
        ),
    }


@make_callable_tool
def create_it_ticket(title: str, priority: str, details: str) -> Dict[str, Any]:
    """
    Create an official IT Service Management (ITSM) incident ticket.

    Args:
        title: Short descriptive title of the incident.
        priority: Severity priority ('Low', 'Medium', 'High', 'Critical').
        details: Complete diagnostic summary, root cause, and escalation reasons.

    Returns:
        Dictionary containing ticket ID, assigned support team, and timestamp.
    """
    try:
        return _raw_create_it_ticket(title, priority, details)
    except Exception as e:
        return {"status": "ERROR", "error": f"Failed creating ticket: {str(e)}"}


def get_all_created_tickets() -> List[Dict[str, Any]]:
    """Retrieve all tickets created in the current system session."""
    with _TICKETS_LOCK:
        return list(IT_TICKETS_DB)


def get_all_security_violations() -> List[Dict[str, Any]]:
    """Retrieve all tool safety violations intercepted during execution."""
    with _SECURITY_LOGS_LOCK:
        return list(TOOL_SECURITY_LOGS)
