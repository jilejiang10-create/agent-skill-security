# Agent Skill Security

![Security Scan](https://github.com/jilejiang10-create/agent-skill-security/actions/workflows/security-scan.yml/badge.svg)

An open-source security scanner for AI Agents, Plugins, Skills, and automation scripts.

Built to help developers detect security risks in AI agent workflows before deployment.

Agent Skill Security provides automated security analysis for AI-powered applications by detecting prompt injection, secret exposure, unsafe code execution, and risky operations.


## Why This Project

AI Agents are becoming increasingly powerful. They can:

- Execute code
- Call external tools
- Access local files
- Send network requests
- Process external instructions

These capabilities introduce new security challenges.

Without proper security checks, Agent Skills may introduce:

- Prompt injection attacks
- Secret and API key exposure
- Dangerous command execution
- Unsafe filesystem operations
- Unauthorized network requests

Agent Skill Security provides a lightweight security layer designed for the AI Agent ecosystem.

It helps developers evaluate security risks before deploying AI-powered workflows.


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


## Detection Categories


| Category | Description |
|---|---|
| Prompt Injection | Detects malicious instructions attempting to override agent behavior |
| Secret Exposure | Finds leaked API keys and credentials |
| Dangerous Commands | Detects unsafe shell execution |
| File Operations | Identifies risky filesystem modifications |
| Network Access | Analyzes external request risks |


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
python -m pip install -e ".[web]"
```

For development and tests:

```bash
python -m pip install -e ".[web,test]"
```


## Usage


### Streamlit Dashboard


Run:

```bash
streamlit run src/agent_skill_security/app.py
```

The dashboard only scans inside its configured root directory. By default this
is the directory where Streamlit is started. Administrators can set an explicit
root before launch:

```bash
AGENT_SKILL_SECURITY_SCAN_ROOT=/srv/projects streamlit run src/agent_skill_security/app.py
```

Targets entered in the dashboard are resolved against that root. Escaping
paths and external symbolic links are rejected or skipped. To protect the Web
process from resource exhaustion, it scans at most 10,000 files, 5 MiB per
file, and 5,000 findings per file by default. Administrators can change these
limits with `AGENT_SKILL_SECURITY_MAX_FILES`,
`AGENT_SKILL_SECURITY_MAX_FILE_SIZE`, and
`AGENT_SKILL_SECURITY_MAX_FINDINGS_PER_FILE`. Truncation is explicitly shown
in the report. CLI scans remain unlimited unless limits are passed through the
Python API.


Open:

```
http://localhost:8501
```


### Command Line


Example:

```bash
agent-security ./your-agent-project
```

The CLI remains a local tool and can scan any directory the current user can
read. It is not restricted by the Web dashboard's scan root.


## Example Detection


Example dangerous code:

```python
import os

os.system("rm -rf /")
```


Detected:

```
Risk Score: 30/100
Risk Level: MEDIUM

Finding:
dangerous_shell
```


## Testing


Run:

```bash
python -m pytest
```


The regression suite covers report injection, secret redaction, path boundary
enforcement, risk consistency, rule compatibility, and all output formats.
The CI self-scan transparently suppresses only four rule-definition literals;
each suppression is bound to its exact file, rule, line, column, and line hash.


## Report Data Contract

Every interface consumes the same scan result. A result contains the target,
scan-completeness flag, files seen/scanned, skipped and truncated files, scan
errors, normalized findings, total issue count, and one canonical risk object.
The following invariant is tested:

```text
total_issues == len(findings) == risk.total_findings
```

Secret evidence is replaced with `[REDACTED]` before it enters the result, so it
cannot be exposed by the CLI, Streamlit, JSON, or HTML report. HTML report text
is escaped and protected with a restrictive Content Security Policy.

If coverage is limited by resource bounds, skipped files, truncation, or read
errors, every interface reports `SCAN INCOMPLETE`; a `LOW` observed score is
never presented as a complete clean scan in that case.


## Security Scope


This project focuses on security analysis for:

- AI Agent Skills
- Plugins
- Automation Scripts
- Developer Tools
- LLM-based Applications


## Open Source Value


Agent Skill Security helps the open-source AI ecosystem by providing developers with a practical security tool for evaluating AI Agents, Plugins, and Skills.

As AI agent adoption grows, security validation becomes an important part of responsible AI development.


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
