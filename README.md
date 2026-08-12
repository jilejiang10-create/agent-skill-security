# Agent Skill Security

Open-source security scanner for AI agents, skills, plugins, and automation scripts.

## Features

- 🔍 Prompt Injection Detection
- 🔑 Hardcoded API Key Detection
- ⚠️ Dangerous Shell Command Detection
- 🌐 Network Request Risk Detection
- 📁 File System Operation Detection
- 📊 Risk Score Calculation
- 📝 Security Report Generation


## Architecture

```text
Agent Project
      |
      v
Scanner Engine
      |
      v
Security Rules
      |
      v
Risk Scoring
      |
      v
Security Report
```


## Installation

```bash
git clone https://github.com/jilejiang10-create/agent-skill-security.git

cd agent-skill-security

pip install -e .
```


## Usage

Scan an AI agent project:

```bash
python -m agent_skill_security.cli ./your-agent
```


Example output:

```text
Security Report

Risk Level: HIGH

Findings:

- Hardcoded API Key
- Prompt Injection Risk
- Dangerous Shell Command
```


## Roadmap

- Basic scanner
- Risk scoring
- Report generator
- Web dashboard
- AI security assistant
- CI/CD integration


## License

MIT License
