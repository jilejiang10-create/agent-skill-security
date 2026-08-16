# Agent Skill Security

![Security Scan](https://github.com/jilejiang10-create/agent-skill-security/actions/workflows/security-scan.yml/badge.svg)


Open-source security scanner for AI agents, skills, plugins, and automation scripts.

Detect security risks including:

- Prompt Injection
- Secret Exposure
- Dangerous Code Execution
- Unsafe Network Requests


## Features

- 🔍 Prompt Injection Detection
- 🔑 Hardcoded API Key Detection
- ⚠️ Dangerous Shell Command Detection
- 🌐 Network Request Risk Detection
- 📁 File System Operation Detection
- 📊 Risk Score Calculation
- 📄 Security Report Generation


## Architecture


```
Agent Project

        |
        v

Scanner Engine

        |
        v

Security Rules

        |
        v

Risk Analyzer

        |
        v

Security Report
```


## Installation


Clone repository:


```bash
git clone https://github.com/jilejiang10-create/agent-skill-security.git

cd agent-skill-security
```


Install dependencies:


```bash
pip install -r requirements.txt
```


## Usage


Run scanner:


```bash
PYTHONPATH=src python -m agent_skill_security.cli
```


or


```bash
agent-security
```


## Example Output


```
Security Scan Report
================================

File:
example.py

Risk:
Secret Exposure

Keyword:
api_key

--------------------
```


## Security Checks


The scanner detects:


### Prompt Injection

Examples:

```
ignore previous instructions
system prompt
jailbreak
```


### Secret Leakage

Examples:

```
api_key
password
token
secret
```


### Dangerous Commands

Examples:

```
rm -rf
os.system
subprocess
```


### Unsafe Network Requests

Examples:

```
requests.get
urllib
curl
```


## Development


Install development dependencies:


```bash
pip install -r requirements.txt
```


Run tests:


```bash
pytest
```


## License

MIT License
