
# Threat Detection & Digital Forensics Engine

A Python-based cybersecurity investigation tool that detects
suspicious authentication activity and produces forensic reports.

## Features

- Brute-force login detection
- Password-spraying detection
- Chronological incident reconstruction
- SHA-256 evidence fingerprinting
- Structured JSON investigation reports
- Automated testing with pytest

## Technologies

Python 3.11, pytest, Git, JSON.

## Getting Started

Create a virtual environment:

```powershell
python -m venv .venv
```

Install testing dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Run the detector:

```powershell
.\.venv\Scripts\python.exe .\src\threat_engine\detector.py .\data\samples\auth_events.jsonl --report .\reports\investigation_report.json
```

Run automated tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

## Example Results

The included synthetic dataset contains 11 authentication events.

Expected detections:
- One brute-force alert
- One password-spraying alert

The initial automated test suite contains 12 passing tests.

## Security and Forensic Limitations

This is an educational prototype using synthetic data.

Detection rules identify suspicious patterns but do not
conclusively establish malicious intent.

SHA-256 hashing supports integrity checking against a trusted
baseline but does not independently prove evidence authenticity
or establish a complete chain of custody.
