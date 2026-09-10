"""Synthetic traffic generator — creates realistic benign and attack traffic patterns.

Used to train the ML anomaly detector and power live demonstrations without
requiring real packet captures.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinelwall.core.events import EventType, NetworkEvent, Protocol, Severity

_RANDOM = random.Random(0xC0FFEE)


def generate_benign_traffic(
    hour_offset: float = 0.0,
    seed: int | None = None,
    duration_minutes: int = 60,
    samples_per_minute: int = 5,
) -> list[NetworkEvent]:
    """Generate realistic benign LAN/WAN traffic for ML baseline training."""
    if seed is not None:
        local_rng = random.Random(seed)
    else:
        local_rng = _RANDOM

    internal_hosts = [f"10.0.{local_rng.randint(1, 5)}.{local_rng.randint(2, 254)}" for _ in range(12)]
    dns_servers = ["8.8.8.8", "1.1.1.1", "10.0.0.53"]
    web_servers = ["142.250.72.14", "151.101.0.223", "172.217.0.110"]
    mail_servers = ["173.194.76.27", "209.85.202.27"]
    ntp_servers = ["162.159.200.1", "129.6.15.28"]

    events: list[NetworkEvent] = []
    start = datetime.now(timezone.utc) - timedelta(minutes=duration_minutes)
    start += timedelta(hours=hour_offset)

    common_domains = [
        "google.com", "microsoft.com", "github.com", "cloudflare.com",
        "amazon.com", "stackoverflow.com", "wikipedia.org", "youtube.com",
        "reddit.com", "nytimes.com", "netflix.com", "spotify.com",
    ]

    t = start
    ev_idx = 0
    while ev_idx < duration_minutes * samples_per_minute:
        host = local_rng.choice(internal_hosts)
        roll = local_rng.random()
        if roll < 0.35:
            domain = local_rng.choice(common_domains)
            events.append(_dns_query(host, "8.8.8.8", domain, t, local_rng))
        elif roll < 0.65:
            server = local_rng.choice(web_servers)
            events.append(_http_get(host, server, local_rng, t))
        elif roll < 0.8:
            ntp = local_rng.choice(ntp_servers)
            events.append(_udp_conn(host, ntp, 123, 40, t))
        elif roll < 0.9:
            mail = local_rng.choice(mail_servers)
            events.append(_smtp_conn(host, mail, t, local_rng))
        else:
            dns = local_rng.choice(dns_servers)
            events.append(_dns_query(host, dns, f"cdn-{local_rng.randint(1, 90)}.edge.example.net", t, local_rng))

        t += timedelta(seconds=60 / samples_per_minute)
        ev_idx += 1

    return events


def generate_attack_scenario(scenario: str = "multi-stage", seed: int = 0xC0FFEE) -> tuple[list[NetworkEvent], list[str]]:
    """Generate a realistic multi-stage attack scenario.

    Returns (events, ground_truth_techniques).
    """
    random.seed(seed)
    handlers = {
        "multi-stage": _scenario_multi_stage,
        "exfiltration": _scenario_exfiltration,
        "brute-force": _scenario_brute_force,
        "lateral-movement": _scenario_lateral_movement,
        "c2-beacon": _scenario_c2_beacon,
        "dns-tunneling": _scenario_dns_tunneling,
    }
    handler = handlers.get(scenario)
    if not handler:
        return [], []
    return handler()

def _scenario_multi_stage() -> tuple[list[NetworkEvent], list[str]]:
    """Full kill chain: recon → brute force → access → C2 → exfil."""
    attacker = "185.220.101.34"
    target = "10.0.1.5"
    events: list[NetworkEvent] = []
    t = datetime.now(timezone.utc) - timedelta(minutes=45)

    # Phase 1: reconnaissance (T1046, T1018)
    for port in [22, 80, 443, 445, 3389, 8080, 8443, 5900, 21, 25, 88, 389, 5985, 5986]:
        events.append(_port_scan_probe(attacker, target, port, t))
        t += timedelta(seconds=random.uniform(0.1, 1.5))
    events.append(_icmp_ping(attacker, target, t, size=40))
    t += timedelta(seconds=5)

    # Phase 2: brute force SSH (T1110)
    for i in range(8):
        events.append(_ssh_auth_failure(attacker, target, t, i))
        t += timedelta(seconds=random.uniform(0.3, 1.2))
    events.append(_ssh_auth_success(attacker, target, t))
    t += timedelta(seconds=30)

    # Phase 3: C2 beaconing (T1071, T1572)
    for i in range(6):
        events.append(_beacon(attacker, target, t, i))
        t += timedelta(seconds=20)

    # Phase 4: data staging + exfiltration (T1560, T1048)
    events.append(_large_encrypted_transfer(target, attacker, t))
    t += timedelta(seconds=10)

    # Phase 5: lateral movement attempt (T1021)
    events.append(_smb_connect(target, "10.0.1.6", t))
    events.append(_smb_connect(target, "10.0.1.7", t))
    events.append(_smb_connect(target, "10.0.1.8", t))

    techniques = ["T1046", "T1018", "T1110", "T1078", "T1071", "T1572", "T1560", "T1048", "T1021"]
    return events, techniques


def _scenario_exfiltration() -> tuple[list[NetworkEvent], list[str]]:
    attacker = "203.0.113.77"
    target = "10.0.2.10"
    events: list[NetworkEvent] = []
    t = datetime.now(timezone.utc) - timedelta(minutes=20)
    for i in range(10):
        events.append(_dns_query(target, "8.8.8.8", f"data{1000+i}.exfil-evil.org", t, random))
        t += timedelta(seconds=8)
    events.append(_large_encrypted_transfer(target, attacker, t))
    metrics = _large_encrypted_transfer(target, attacker, t)
    return events, ["T1048", "T1071", "T1041", "T1560"]


def _scenario_brute_force() -> tuple[list[NetworkEvent], list[str]]:
    attacker = "198.51.100.23"
    target = "10.0.3.9"
    events: list[NetworkEvent] = []
    t = datetime.now(timezone.utc) - timedelta(minutes=10)
    for i in range(15):
        events.append(_ssh_auth_failure(attacker, target, t, i))
        t += timedelta(seconds=random.uniform(0.2, 1.0))
    return events, ["T1110"]


def _scenario_lateral_movement() -> tuple[list[NetworkEvent], list[str]]:
    src = "10.0.4.15"
    events: list[NetworkEvent] = []
    t = datetime.now(timezone.utc) - timedelta(minutes=15)
    targets = [f"10.0.4.{i}" for i in range(20, 31)]
    for i, tgt in enumerate(targets):
        events.append(_smb_connect(src, tgt, t))
        t += timedelta(seconds=random.uniform(1, 3))
    return events, ["T1021", "T1083"]


def _scenario_c2_beacon() -> tuple[list[NetworkEvent], list[str]]:
    attacker = "185.220.41.99"
    victim = "10.0.5.20"
    events: list[NetworkEvent] = []
    t = datetime.now(timezone.utc) - timedelta(hours=2)
    for i in range(10):
        events.append(_http_post(victim, attacker, random, t, size=random.randint(500, 2000)))
        t += timedelta(seconds=60)
    events.append(_large_encrypted_transfer(victim, attacker, t))
    return events, ["T1071", "T1572", "T1048"]


def _scenario_dns_tunneling() -> tuple[list[NetworkEvent], list[str]]:
    victim = "10.0.6.30"
    server = "8.8.8.8"
    events: list[NetworkEvent] = []
    t = datetime.now(timezone.utc) - timedelta(minutes=30)
    for i in range(8):
        blob = "".join(random.choices("abcdef0123456789", k=40))
        events.append(_dns_query(victim, server, f"{blob}.dns-exfil.attacker.net", t, random))
        t += timedelta(seconds=15)
    return events, ["T1071", "T1048"]


# --- Event factory helpers ---

def _port_scan_probe(src: str, dst: str, port: int, t: datetime) -> NetworkEvent:
    """Sequential connection attempt to distinct ports."""
    return NetworkEvent(
        timestamp=t, source_ip=src, destination_ip=dst,
        source_port=random.randint(40000, 60000), destination_port=port,
        protocol=Protocol.TCP, event_type=EventType.PORT_SCAN,
        severity=Severity.MEDIUM, payload_size=0,
        payload_preview="SYN",
        metadata={"scan_context": "sequential_port_probe"},
        tags=["port-scan"],
    )


def _icmp_ping(src: str, dst: str, t: datetime, size: int = 40) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=src, destination_ip=dst,
        source_port=0, destination_port=0,
        protocol=Protocol.ICMP, event_type=EventType.ICMP_ECHO,
        severity=Severity.INFORMATIONAL, payload_size=size,
        metadata={"icmp_type": 8},
    )


def _ssh_auth_failure(src: str, dst: str, t: datetime, attempt: int) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=src, destination_ip=dst,
        source_port=random.randint(40000, 60000), destination_port=22,
        protocol=Protocol.SSH, event_type=EventType.AUTH_FAILURE,
        severity=Severity.MEDIUM, payload_size=random.randint(50, 120),
        payload_preview="SSH-2.0 authentication failure",
        metadata={"reason": "Server: authentication failed", "attempt": attempt},
        tags=["brute-force"],
    )


def _ssh_auth_success(src: str, dst: str, t: datetime) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=src, destination_ip=dst,
        source_port=random.randint(40000, 60000), destination_port=22,
        protocol=Protocol.SSH, event_type=EventType.AUTH_SUCCESS,
        severity=Severity.HIGH, payload_size=810,
        payload_preview="SSH-2.0 authentication success",
        metadata={"reason": "accepted publickey"},
        tags=["auth-success"],
    )


def _beacon(attacker: str, victim: str, t: datetime, index: int) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=victim, destination_ip=attacker,
        source_port=random.randint(50000, 60000), destination_port=443,
        protocol=Protocol.HTTPS, event_type=EventType.C2_BEACON,
        severity=Severity.HIGH, payload_size=random.randint(400, 1500),
        payload_preview="POST /api/v2/beacon",
        metadata={"beacon_index": index, "interval_seconds": 20},
        tags=["c2-beacon"],
    )


def _large_encrypted_transfer(src: str, dst: str, t: datetime) -> NetworkEvent:
    size = random.randint(200000, 400000)
    return NetworkEvent(
        timestamp=t, source_ip=src, destination_ip=dst,
        source_port=random.randint(50000, 60000), destination_port=443,
        protocol=Protocol.HTTPS, event_type=EventType.ENCRYPTED_TRANSFER,
        severity=Severity.HIGH, payload_size=size,
        payload_preview="data.enc (application/octet-stream)",
        metadata={"archive_method": "zip+encrypt", "file_count": random.randint(10, 40)},
        tags=["exfiltration"],
    )


def _smb_connect(src: str, dst: str, t: datetime) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=src, destination_ip=dst,
        source_port=random.randint(40000, 50000), destination_port=445,
        protocol=Protocol.SMB, event_type=EventType.SMB_CONNECT,
        severity=Severity.MEDIUM, payload_size=random.randint(100, 300),
        payload_preview="SMB2 CREATE \\\\\\\\10.0.x.x\\ADMIN$",
        metadata={"command": "SMB2_CONNECT", "share": "ADMIN$"},
        tags=["lateral-movement"],
    )


def _dns_query(host: str, dns_server: str, domain: str, t: datetime, rng: random.Random) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=host, destination_ip=dns_server,
        source_port=random.randint(50000, 60000), destination_port=53,
        protocol=Protocol.DNS, event_type=EventType.DNS_QUERY,
        severity=Severity.INFORMATIONAL, payload_size=len(domain) + 20,
        payload_preview=f"query: {domain[:40]}",
        metadata={"query_name": domain, "qtype": "A"},
    )


def _http_get(host: str, server: str, rng: random.Random, t: datetime) -> NetworkEvent:
    paths = ["/", "/index.html", "/api/status", "/assets/app.js", "/images/logo.png"]
    path = rng.choice(paths)
    return NetworkEvent(
        timestamp=t, source_ip=host, destination_ip=server,
        source_port=random.randint(40000, 60000), destination_port=80,
        protocol=Protocol.HTTP, event_type=EventType.HTTP_REQUEST,
        severity=Severity.INFORMATIONAL, payload_size=random.randint(100, 8000),
        payload_preview=f"GET {path} HTTP/1.1",
        metadata={"method": "GET", "path": path, "host": server},
    )


def _http_post(host: str, server: str, rng: random.Random, t: datetime, size: int = 500) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=host, destination_ip=server,
        source_port=random.randint(40000, 60000), destination_port=443,
        protocol=Protocol.HTTPS, event_type=EventType.HTTP_REQUEST,
        severity=Severity.MEDIUM, payload_size=size,
        payload_preview="POST /control HTTP/1.1",
        metadata={"method": "POST", "path": "/control", "host": server},
        tags=["c2-beacon"],
    )


def _udp_conn(host: str, server: str, port: int, size: int, t: datetime) -> NetworkEvent:
    return NetworkEvent(
        timestamp=t, source_ip=host, destination_ip=server,
        source_port=random.randint(30000, 50000), destination_port=port,
        protocol=Protocol.UDP, event_type=EventType.CONNECTION,
        severity=Severity.INFORMATIONAL, payload_size=size,
    )


def _smtp_conn(host: str, server: str, t: datetime, rng: random.Random) -> NetworkEvent:
    size = rng.randint(500, 5000)
    return NetworkEvent(
        timestamp=t, source_ip=host, destination_ip=server,
        source_port=random.randint(40000, 60000), destination_port=587,
        protocol=Protocol.SMTP, event_type=EventType.CONNECTION,
        severity=Severity.INFORMATIONAL, payload_size=size,
        payload_preview="EHLO mail.example.local",
    )