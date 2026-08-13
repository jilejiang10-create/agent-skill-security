# Agent Skill Security

Open-source security scanner for AI agents, skills, plugins, and automation scripts.

Detect security risks including prompt injection, secret exposure, dangerous code execution, and unsafe network operations.


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
Risk Analyzer
      |
      v
Security Report



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
python -m agent_skill_security.app
```

or

```bash
python -m agent_skill_security.cli

```
