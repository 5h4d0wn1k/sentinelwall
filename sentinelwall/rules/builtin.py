"""Built-in detection rules for SentinelWall."""

from __future__ import annotations

from sentinelwall.core.events import Severity
from sentinelwall.rules.parser import Rule, RuleCondition


def _make_rule(
    name: str, desc: str, severity: str, conditions: list[tuple[str, str, object]],
    techniques: list[str] | None = None, tags: list[str] | None = None,
    logic: str = "and",
) -> Rule:
    conds = [RuleCondition(field=f, operator=op, value=v) for f, op, v in conditions]
    return Rule(
        name=name, description=desc,
        severity=Severity[severity.upper()],
        conditions=conds, condition_logic=logic,
        techniques=techniques or [], tags=tags or [],
    )


BUILTIN_RULES: list[Rule] = [
    _make_rule(
        "port_scan_high_volume",
        "High-volume sequential port scanning detected",
        "HIGH",
        [("event_type", "eq", "PORT_SCAN")],
        techniques=["T1046", "T1018"], tags=["port-scan", "reconnaissance"],
    ),
    _make_rule(
        "ssh_non_standard_port",
        "SSH service running on non-standard port suggests tunneling",
        "MEDIUM",
        [("event_type", "eq", "SSH_HANDSHAKE"), ("destination_port", "neq", "22")],
        techniques=["T1572"], tags=["protocol-anomaly", "tunneling"],
    ),
    _make_rule(
        "large_encrypted_transfer",
        "Large encrypted data transfer may indicate exfiltration",
        "HIGH",
        [("event_type", "eq", "ENCRYPTED_TRANSFER"), ("payload_size", "gt", 100000)],
        techniques=["T1048", "T1041"], tags=["exfiltration"],
    ),
    _make_rule(
        "dns_query_long_subdomain",
        "DNS query with abnormally long subdomain suggests DNS tunneling",
        "HIGH",
        [("event_type", "eq", "DNS_QUERY"), ("payload_size", "gt", 200)],
        techniques=["T1071", "T1048"], tags=["dns-tunneling", "exfiltration"],
    ),
    _make_rule(
        "smb_lateral_movement",
        "Internal SMB connection to multiple hosts suggests lateral movement",
        "HIGH",
        [("event_type", "eq", "SMB_CONNECT"), ("lateral_movement_candidate", "eq", True)],
        techniques=["T1021"], tags=["lateral-movement"],
    ),
    _make_rule(
        "brute_force_auth_failure",
        "Authentication failure detected — potential brute force attempt",
        "MEDIUM",
        [("event_type", "eq", "AUTH_FAILURE")],
        techniques=["T1110"], tags=["brute-force", "credential-access"],
    ),
    _make_rule(
        "icmp_large_payload",
        "Large ICMP packet suggests covert channel or tunneling",
        "MEDIUM",
        [("event_type", "eq", "ICMP_ECHO"), ("payload_size", "gt", 1000)],
        techniques=["T1095"], tags=["covert-channel"],
    ),
    _make_rule(
        "rdp_external_access",
        "External RDP access attempt detected",
        "HIGH",
        [("event_type", "eq", "SSH_HANDSHAKE"), ("destination_port", "eq", "3389")],
        techniques=["T1021", "T1133"], tags=["remote-access", "external"],
    ),
    _make_rule(
        "http_post_large_upload",
        "HTTP POST with large payload may indicate data upload",
        "MEDIUM",
        [("event_type", "eq", "HTTP_REQUEST"), ("payload_size", "gt", 50000)],
        techniques=["T1048"], tags=["data-transfer"],
    ),
    _make_rule(
        "sensitive_port_access",
        "Access to sensitive management port detected",
        "MEDIUM",
        [("destination_port", "in", [5985, 5986, 9090, 8443])],
        techniques=["T1021"], tags=["management-access"],
    ),
    _make_rule(
        "encrypted_transfer_internal",
        "Large internal encrypted transfer may indicate lateral data movement",
        "MEDIUM",
        [("event_type", "eq", "ENCRYPTED_TRANSFER"), ("payload_size", "gt", 50000),
         ("direction", "eq", "outbound")],
        techniques=["T1048", "T1560"], tags=["exfiltration", "data-movement"],
    ),
    _make_rule(
        "ftp_data_transfer",
        "FTP data transfer detected — potential file exfiltration",
        "MEDIUM",
        [("event_type", "eq", "DATA_TRANSFER"), ("destination_port", "eq", "20")],
        techniques=["T1048"], tags=["exfiltration", "ftp"],
    ),
    _make_rule(
        "vnc_remote_access",
        "VNC remote desktop connection detected",
        "MEDIUM",
        [("destination_port", "in", [5900, 5901, 5902])],
        techniques=["T1021"], tags=["remote-access"],
    ),
    _make_rule(
        "ntp_reconnaissance",
        "NTP monlist or similar reconnaissance command detected",
        "LOW",
        [("event_type", "eq", "DNS_QUERY"), ("destination_port", "eq", "123")],
        techniques=["T1046"], tags=["reconnaissance", "ntp"],
    ),
    _make_rule(
        "smtp_data_exfil",
        "Outbound SMTP with large payload may indicate email-based exfiltration",
        "HIGH",
        [("event_type", "eq", "HTTP_REQUEST"), ("destination_port", "in", [25, 587, 465]),
         ("payload_size", "gt", 10000)],
        techniques=["T1048", "T1041"], tags=["exfiltration", "email"],
    ),
    _make_rule(
        "tls_certificate_anomaly",
        "TLS handshake with suspicious metadata",
        "MEDIUM",
        [("event_type", "eq", "TLS_HANDSHAKE"), ("payload_preview", "contains", "self-signed")],
        techniques=["T1572"], tags=["tls-anomaly"],
    ),
    _make_rule(
        "kerberoasting",
        "Unusual Kerberos service ticket request pattern",
        "HIGH",
        [("event_type", "eq", "DNS_QUERY"), ("destination_port", "eq", "88"),
         ("payload_size", "gt", 500)],
        techniques=["T1558"], tags=["credential-access", "kerberos"],
    ),
    _make_rule(
        "icmp_tunneling_suspected",
        "High-frequency ICMP with data payload — tunneling suspected",
        "HIGH",
        [("event_type", "eq", "ICMP_ECHO"), ("payload_size", "gt", 500),
         ("payload_size", "lt", 65535)],
        techniques=["T1095", "T1572"], tags=["covert-channel", "tunneling"],
    ),
]
