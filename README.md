# Agent Skill Security

![Security Scan](https://github.com/jilejiang10-create/agent-skill-security/actions/workflows/security-scan.yml/badge.svg)

An open-source security scanner for AI Agents, Plugins, Skills, and automation scripts.

Agent Skill Security helps developers identify security risks before deploying AI-powered workflows.

## Why This Project

AI Agents and automation tools can execute code, access files, communicate with networks, and process external instructions.

Without security checks, Agent Skills may introduce:

- Prompt injection attacks
- Secret and API key exposure
- Dangerous command execution
- Unsafe filesystem operations
- Unauthorized network requests

Agent Skill Security provides an automated security layer for AI Agent ecosystems.

## Features

### Security Detection

Detects:

- Prompt injection patterns
- Hardcoded API keys and secrets
- Dangerous shell commands
- Unsafe Python execution
- Network request risks
- Filesystem modification risks

### Risk Assessment

The scanner provides:

- Risk score calculation
- Severity classification
- Security report generation

Risk levels:

| Score | Level |
|---|---|
| 80-100 | Critical |
| 40-79 | High |
| 15-39 | Medium |
| 0-14 | Low |

### Multiple Interfaces

Supported:

- Streamlit Web Dashboard
- Command Line Interface (CLI)
- JSON Security Reports
- HTML Reports

## Architecture

```
agent-skill-security

├── scanner.py
│   Security pattern detection engine

├── rules.py
│   Security detection rules

├── risk.py
│   Risk scoring system

├── report.py
│   Report generator

├── app.py
│   Streamlit dashboard

└── tests/
    Automated security tests
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

### Streamlit Dashboard

Run:

```bash
streamlit run src/agent_skill_security/app.py
```

Open:

```
http://localhost:8501
```

### Command Line

Example:

```bash
python -m agent_skill_security.cli ./your-agent-project
```

## Example Detection

Example dangerous code:

```python
import os

os.system("rm -rf /")
```

Detected:

```
Risk Level: HIGH

Finding:
dangerous_shell
```

## Testing

Run:

```bash
python -m pytest
```

Current test status:

```
7 passed
```

## Security Scope

This project focuses on security analysis for:

- AI Agent Skills
- Plugins
- Automation Scripts
- Developer Tools
- LLM-based Applications

## Roadmap

Future improvements:

- More AI Agent attack patterns
- LLM-based security analysis
- Plugin sandbox detection
- Supply-chain security checks
- Security rule marketplace

## Contributing

Contributions are welcome.

Please read:

- CONTRIBUTING.md
- SECURITY.md

before submitting changes.

## License

MIT License

Copyright (c) 2026 jilejiang10-create
