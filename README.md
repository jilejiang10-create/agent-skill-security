# Agent Skill Security

Open-source security scanner for AI Agents, Agent Skills, Plugins, and automation workflows.

Agent Skill Security helps developers identify security risks before allowing AI Agents to execute external skills, tools, or automation scripts.

It detects prompt injection attacks, secret exposure, unsafe code execution, risky network requests, and dangerous filesystem operations.

The goal of this project is to improve AI Agent security by providing automated security analysis before deployment.


---

# Why Agent Security Matters

Modern AI Agents are becoming increasingly powerful.

They can:

- Execute code
- Access local files
- Call external APIs
- Use third-party tools
- Run automation workflows


These capabilities introduce new security risks.

Traditional application security tools are often not designed for AI Agent specific threats such as:

- Prompt injection
- Malicious Agent Skills
- Unsafe tool execution
- Hidden instructions
- Credential leakage


Agent Skill Security focuses on securing the emerging AI Agent ecosystem.


---

# Security Risks Detected


## 1. Prompt Injection Detection

Detect malicious instructions that attempt to manipulate AI Agent behavior.

Examples:

- Ignore previous instructions
- Reveal system prompt
- Bypass security rules
- Override developer instructions
- Attempt jailbreak behaviors


---

## 2. Secret Exposure Detection

Detect exposed sensitive information.

Detected examples:

- API Keys
- Secret Keys
- Hardcoded Credentials
- Authentication Tokens
- Private configuration values


---

## 3. Dangerous Code Execution Detection

Detect potentially unsafe execution patterns.

Examples:

- os.system()
- subprocess execution
- Shell commands
- Destructive commands
- Unsafe automation actions


---

## 4. Unsafe Network Request Detection

Detect risky external communication.

Examples:

- requests
- httpx
- urllib
- External API calls
- Untrusted network connections


---

## 5. File System Risk Detection

Detect dangerous filesystem operations.

Examples:

- File deletion
- Recursive removal
- Unauthorized writing
- Potential filesystem damage


---

# Features


## Security Scanner

Automatically scans project files and detects suspicious security patterns.


## Risk Score Engine

Calculates security risk based on detected issues.


Risk Levels:

```
0-19     LOW
20-49    MEDIUM
50-79    HIGH
80-100   CRITICAL
```


## Security Report Generation

Supports:

- Text Report
- HTML Report
- JSON Report


## Streamlit Security Dashboard

Provides a visual security interface:

- Scan projects
- View security findings
- Check risk score
- View risk level
- Export reports


---

# AI Agent Security Use Cases


Agent Skill Security can help secure:

- AI Agent frameworks
- Agent Skills
- LLM Plugins
- Tool calling workflows
- Automation scripts
- Developer AI assistants


Typical usage scenarios:

- Reviewing third-party Agent Skills before installation
- Scanning automation scripts before execution
- Detecting malicious instructions in AI workflows
- Preventing accidental credential exposure
- Improving AI Agent deployment security


---

# Architecture


```
Agent Skill Security

│
├── Scanner
│
├── File Scanner
│
├── Pattern Detection
│
└── Prompt Analysis
│
├── Risk Engine
│
├── Risk Calculation
│
└── Risk Classification
│
├── Report System
│
├── Text Report
│
├── HTML Report
│
└── JSON Report
│
└── Dashboard

    └── Streamlit UI
```


---

# Installation


Clone repository:

```bash
git clone https://github.com/jilejiang10-create/agent-skill-security.git
```


Enter project directory:

```bash
cd agent-skill-security
```


Install dependencies:

```bash
pip install -r requirements.txt
```


---

# Usage


## Start Security Dashboard


Run:

```bash
streamlit run src/agent_skill_security/app.py
```


Open browser:

```
http://localhost:8501
```


---

## Command Line Scanner


Run:

```bash
agent-scan target_path
```


Example:

```bash
agent-scan tests/malicious_samples
```


---

# Project Structure


```
agent-skill-security

├── .github
│
├── src
│   └── agent_skill_security
│       ├── scanner.py
│       ├── rules.py
│       ├── risk.py
│       ├── report.py
│       ├── cli.py
│       └── app.py
│
├── tests
│
├── docs
│
├── SECURITY.md
│
├── CONTRIBUTING.md
│
├── pyproject.toml
│
├── requirements.txt
│
└── README.md
```


---

# Security Philosophy


Agent Skill Security follows these principles:


- Detect before execution
- Minimize AI Agent permissions
- Protect sensitive information
- Validate external tools and skills
- Improve AI automation safety


---

# Roadmap


Future improvements:


- More AI Agent security rules
- LLM behavior analysis
- Plugin permission analysis
- CI/CD security integration
- Vulnerability database integration
- Advanced Agent behavior monitoring


---

# Contributing


Contributions are welcome.


You can contribute:


- Bug reports
- Security improvements
- New detection rules
- Feature requests
- Documentation improvements


Please read:

```
CONTRIBUTING.md
```


---

# License


MIT License


---

# Author


Created by:

**jilejiang10-create**


GitHub:

https://github.com/jilejiang10-create/agent-skill-security
