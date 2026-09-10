"""MITRE ATT&CK technique database with detection signatures."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinelwall.core.events import EventType, Protocol, Severity


@dataclass(frozen=True)
class TechniqueInfo:
    """Complete MITRE ATT&CK technique metadata."""
    technique_id: str
    name: str
    tactic: str
    description: str
    severity: Severity
    detection_patterns: list[str] = field(default_factory=list)
    protocol_hints: list[str] = field(default_factory=list)
    port_hints: list[int] = field(default_factory=list)
    event_type_hints: list[str] = field(default_factory=list)
    sub_techniques: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "description": self.description,
            "severity": self.severity.name,
            "detection_patterns": self.detection_patterns,
            "protocol_hints": self.protocol_hints,
            "port_hints": self.port_hints,
            "sub_techniques": self.sub_techniques,
        }


MITRE_TECHNIQUES: dict[str, TechniqueInfo] = {
    "T1046": TechniqueInfo(
        technique_id="T1046",
        name="Network Service Discovery",
        tactic="discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.",
        severity=Severity.MEDIUM,
        detection_patterns=["port_scan", "sequential_ports", "half_open"],
        protocol_hints=["tcp", "icmp"],
        port_hints=[],
        event_type_hints=["PORT_SCAN"],
    ),
    "T1071": TechniqueInfo(
        technique_id="T1071",
        name="Application Layer Protocol",
        tactic="command-and-control",
        description="Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering.",
        severity=Severity.HIGH,
        detection_patterns=["beacon", "regular_interval", "http POST", "dns query"],
        protocol_hints=["http", "dns", "smtp", "ftp"],
        event_type_hints=["C2_BEACON", "HTTP_REQUEST", "DNS_QUERY"],
        sub_techniques={
            "T1071.001": "Web Protocols (HTTP/S)",
            "T1071.002": "File Transfer Protocols",
            "T1071.003": "Mail Protocols",
            "T1071.004": "DNS",
        },
    ),
    "T1048": TechniqueInfo(
        technique_id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic="exfiltration",
        description="Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel.",
        severity=Severity.HIGH,
        detection_patterns=["large transfer", "encrypted", "non_standard_port", "dns_tunnel"],
        protocol_hints=["dns", "icmp", "http", "https"],
        event_type_hints=["DATA_TRANSFER", "ENCRYPTED_TRANSFER", "EXFILTRATION"],
    ),
    "T1572": TechniqueInfo(
        technique_id="T1572",
        name="Protocol Tunneling",
        tactic="command-and-control",
        description="Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection.",
        severity=Severity.HIGH,
        detection_patterns=["ssh_non_standard", "dns_tunnel", "icmp_tunnel", "http_tunnel"],
        protocol_hints=["ssh", "dns", "icmp"],
        event_type_hints=["SSH_HANDSHAKE", "DNS_QUERY", "ICMP_ECHO"],
    ),
    "T1021": TechniqueInfo(
        technique_id="T1021",
        name="Remote Services",
        tactic="lateral-movement",
        description="Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
        severity=Severity.HIGH,
        detection_patterns=["lateral_movement", "internal_to_internal", "management_port"],
        protocol_hints=["ssh", "smb", "rdp", "vnc"],
        port_hints=[22, 23, 445, 139, 3389, 5985, 5986],
        event_type_hints=["SSH_HANDSHAKE", "SMB_CONNECT", "SMB_TRANSACTION"],
    ),
    "T1110": TechniqueInfo(
        technique_id="T1110",
        name="Brute Force",
        tactic="credential-access",
        description="Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        severity=Severity.HIGH,
        detection_patterns=["auth_failure", "multiple_failures", "success_after_failure"],
        protocol_hints=["ssh", "http", "smb", "rdp", "ldap"],
        event_type_hints=["AUTH_FAILURE", "AUTH_SUCCESS"],
    ),
    "T1078": TechniqueInfo(
        technique_id="T1078",
        name="Valid Accounts",
        tactic="persistence",
        description="Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        severity=Severity.HIGH,
        detection_patterns=["auth_after_brute", "unusual_time", "new_source"],
        protocol_hints=["ssh", "http", "smb", "rdp"],
        event_type_hints=["AUTH_SUCCESS"],
    ),
    "T1041": TechniqueInfo(
        technique_id="T1041",
        name="Exfiltration Over C2 Channel",
        tactic="exfiltration",
        description="Adversaries may steal data by exfiltrating it over an existing command and control channel.",
        severity=Severity.HIGH,
        detection_patterns=["data_over_c2", "large_upload", "encrypted_transfer"],
        protocol_hints=["http", "https", "dns"],
        event_type_hints=["DATA_TRANSFER", "ENCRYPTED_TRANSFER"],
    ),
    "T1095": TechniqueInfo(
        technique_id="T1095",
        name="Non-Application Layer Protocol",
        tactic="command-and-control",
        description="Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts.",
        severity=Severity.MEDIUM,
        detection_patterns=["icmp_anomaly", "large_icmp", "unusual_tcp"],
        protocol_hints=["icmp", "tcp", "udp"],
        event_type_hints=["ICMP_ECHO"],
    ),
    "T1560": TechniqueInfo(
        technique_id="T1560",
        name="Archive Collected Data",
        tactic="collection",
        description="An adversary may compress and/or encrypt data that is collected prior to exfiltration.",
        severity=Severity.MEDIUM,
        detection_patterns=["encrypted_transfer", "compression_header", "large_encrypted"],
        protocol_hints=["http", "https", "smb", "ssh"],
        event_type_hints=["ENCRYPTED_TRANSFER", "DATA_TRANSFER"],
    ),
    "T1005": TechniqueInfo(
        technique_id="T1005",
        name="Data from Local System",
        tactic="collection",
        description="Adversaries may search local system sources, such as file systems and configuration files, to find files of interest.",
        severity=Severity.LOW,
        detection_patterns=["file_access", "config_read", "sensitive_path"],
        protocol_hints=["smb", "ssh", "http"],
        event_type_hints=["SMB_TRANSACTION", "DATA_TRANSFER"],
    ),
    "T1083": TechniqueInfo(
        technique_id="T1083",
        name="File and Directory Discovery",
        tactic="discovery",
        description="Adversaries may enumerate files and directories or may search in specific locations of a host or network share.",
        severity=Severity.LOW,
        detection_patterns=["directory_listing", "path_traversal", "file_enum"],
        protocol_hints=["smb", "ssh", "http"],
        event_type_hints=["SMB_TRANSACTION"],
    ),
    "T1053": TechniqueInfo(
        technique_id="T1053",
        name="Scheduled Task/Job",
        tactic="persistence",
        description="Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        severity=Severity.HIGH,
        detection_patterns=["scheduled_task", "cron_job", "at_job"],
        protocol_hints=["ssh", "smb", "rdp"],
        port_hints=[22, 445, 3389],
    ),
    "T1059": TechniqueInfo(
        technique_id="T1059",
        name="Command and Scripting Interpreter",
        tactic="execution",
        description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.",
        severity=Severity.MEDIUM,
        detection_patterns=["shell_command", "script_execution", "powershell", "bash"],
        protocol_hints=["ssh", "smb"],
        event_type_hints=["SSH_HANDSHAKE", "SMB_TRANSACTION"],
    ),
    "T1027": TechniqueInfo(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        tactic="defense-evasion",
        description="Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents.",
        severity=Severity.MEDIUM,
        detection_patterns=["encoded_payload", "base64", "obfuscated"],
        protocol_hints=["http", "dns"],
        event_type_hints=["HTTP_REQUEST", "DNS_QUERY"],
    ),
    "T1082": TechniqueInfo(
        technique_id="T1082",
        name="System Information Discovery",
        tactic="discovery",
        description="An adversary may attempt to get detailed information about the operating system and hardware.",
        severity=Severity.LOW,
        detection_patterns=["system_info", "os_detection", "fingerprint"],
        protocol_hints=["ssh", "http", "smb"],
    ),
    "T1018": TechniqueInfo(
        technique_id="T1018",
        name="Remote System Discovery",
        tactic="discovery",
        description="Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network.",
        severity=Severity.LOW,
        detection_patterns=["port_scan", "network_scan", "host_discovery"],
        protocol_hints=["tcp", "udp", "icmp"],
        event_type_hints=["PORT_SCAN"],
    ),
    "T1133": TechniqueInfo(
        technique_id="T1133",
        name="External Remote Services",
        tactic="persistence",
        description="Adversaries may leverage external-facing remote services to initially access and/or persist within a network.",
        severity=Severity.HIGH,
        detection_patterns=["external_ssh", "external_rdp", "vpn_auth"],
        protocol_hints=["ssh", "rdp", "vnc"],
        port_hints=[22, 3389, 5900],
    ),
    "T1190": TechniqueInfo(
        technique_id="T1190",
        name="Exploit Public-Facing Application",
        tactic="initial-access",
        description="Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands.",
        severity=Severity.CRITICAL,
        detection_patterns=["exploit_attempt", "web_attack", "injection"],
        protocol_hints=["http", "https"],
        port_hints=[80, 443, 8080, 8443],
        event_type_hints=["HTTP_REQUEST"],
    ),
    "T1105": TechniqueInfo(
        technique_id="T1105",
        name="Ingress Tool Transfer",
        tactic="command-and-control",
        description="Adversaries may transfer tools or other files from an external system into a compromised environment.",
        severity=Severity.HIGH,
        detection_patterns=["file_download", "tool_transfer", "remote_file"],
        protocol_hints=["http", "https", "ftp", "smb"],
        event_type_hints=["HTTP_REQUEST", "DATA_TRANSFER"],
    ),
    "T1566": TechniqueInfo(
        technique_id="T1566",
        name="Phishing",
        tactic="initial-access",
        description="Adversaries may send phishing messages to gain access to victim systems.",
        severity=Severity.HIGH,
        detection_patterns=["phishing_link", "malicious_attachment", "email_anomaly"],
        protocol_hints=["smtp", "http"],
        port_hints=[25, 587, 465, 80, 443],
        event_type_hints=["HTTP_REQUEST"],
    ),
    "T1562": TechniqueInfo(
        technique_id="T1562",
        name="Impair Defenses",
        tactic="defense-evasion",
        description="Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms.",
        severity=Severity.CRITICAL,
        detection_patterns=["firewall_disable", "av_kill", "log_clear"],
        protocol_hints=["ssh", "smb", "rdp"],
    ),
    "T1486": TechniqueInfo(
        technique_id="T1486",
        name="Data Encrypted for Impact",
        tactic="impact",
        description="Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        severity=Severity.CRITICAL,
        detection_patterns=["mass_encryption", "ransomware", "file_encryption"],
        protocol_hints=["smb", "ssh"],
        event_type_hints=["SMB_TRANSACTION", "DATA_TRANSFER"],
    ),
}

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]


def get_technique(technique_id: str) -> TechniqueInfo | None:
    return MITRE_TECHNIQUES.get(technique_id)


def get_techniques_for_tactic(tactic: str) -> list[TechniqueInfo]:
    return [t for t in MITRE_TECHNIQUES.values() if t.tactic == tactic]


def get_all_technique_ids() -> list[str]:
    return sorted(MITRE_TECHNIQUES.keys())
