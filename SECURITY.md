# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in SentinelWall, please report it
responsibly by emailing the maintainers or opening a private issue on GitHub.
Do **not** disclose vulnerabilities publicly until a fix is available.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Practices

- SentinelWall runs as a passive analysis engine and does not modify network
  traffic, inject packets, or forward data to external services.
- All data processing is local-only. No telemetry is sent anywhere.
- Exports (STIX, Navigator, HTML) are written to local disk only.
- The ML model trains on synthetic or provided data; no data leaves the system.

## Dependencies

- Core engine: zero external dependencies (pure Python 3.10+)
- Optional extras: scapy, scikit-learn, numpy, flask
- Dev tools: pytest, mypy, ruff
