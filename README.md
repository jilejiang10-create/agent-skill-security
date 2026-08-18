# Agent Skill Security


Open-source security scanner for AI Agents, Plugins, Skills, and Automation Scripts.


Agent Skill Security helps developers detect security risks before deploying AI-powered applications.



==================================================

Overview

==================================================


AI Agents are becoming increasingly powerful.


They can:


- Execute code

- Access files

- Call external APIs

- Interact with external networks



These capabilities introduce security risks.


Agent Skill Security provides automated security scanning to identify dangerous behaviors before deployment.





==================================================

Security Risks Detected

==================================================



1. Prompt Injection Detection


Detect malicious instructions that attempt to manipulate AI Agent behavior.


Examples:


- Ignore previous instructions

- Reveal system prompt

- Bypass security rules

- Override developer instructions





2. Secret Exposure Detection


Detect exposed sensitive information:


- API Keys

- Secret Keys

- Hardcoded Credentials

- Tokens





3. Dangerous Code Execution Detection


Detect potentially unsafe operations:


- os.system()

- subprocess execution

- Shell commands

- Destructive commands





4. Unsafe Network Request Detection


Detect risky external communication:


- requests

- httpx

- urllib

- External API calls





5. File System Risk Detection


Detect dangerous file operations:


- File deletion

- Recursive removal

- Unauthorized writing






==================================================

Features

==================================================



Security Scanner


Automatically scans project files and detects suspicious patterns.






Risk Score Engine


Calculates security risk based on detected issues.


Risk Level:


0-19     LOW


20-49    MEDIUM


50-79    HIGH


80-100   CRITICAL





Security Report Generation


Supports:


- Text Report

- HTML Report

- JSON Report






Streamlit Security Dashboard


Provides visual interface:


- Scan projects

- View findings

- Check risk score

- View security level

- Export reports






==================================================

Architecture

==================================================



Agent Skill Security


|

├── Scanner

│

├── File Scanner

│

├── Pattern Detection

│

└── Prompt Analysis


|

├── Risk Engine

│

├── Risk Calculation

│

└── Risk Classification


|

├── Report System

│

├── Text Report

│

├── HTML Report

│

└── JSON Report


|

└── Dashboard

    └── Streamlit UI






==================================================

Installation

==================================================



Clone repository:



git clone https://github.com/jilejiang10-create/agent-skill-security.git




Enter project directory:



cd agent-skill-security




Install dependencies:



pip install -r requirements.txt






==================================================

Usage

==================================================



Start Dashboard:



streamlit run src/app.py




Open browser:



http://localhost:8501






Command Line Scanner:



python -m agent_skill_security target_path






==================================================

Project Structure

==================================================



agent-skill-security


├── src

│

└── agent_skill_security

    │

    ├── scanner.py

    │

    ├── risk.py

    │

    ├── report.py

    │

    ├── json_export.py

    │

    └── app.py


├── tests


├── docs


├── SECURITY.md


├── pyproject.toml


└── README.md






==================================================

Security Philosophy

==================================================



Agent Skill Security follows these principles:


- Detect before execution

- Minimize AI Agent permissions

- Protect sensitive information

- Improve AI automation safety






==================================================

Roadmap

==================================================



Future improvements:


- More AI Agent security rules

- LLM behavior analysis

- Plugin permission analysis

- CI/CD security integration

- Vulnerability database integration






==================================================

Contributing

==================================================



Contributions are welcome.



You can contribute:


- Bug reports

- Security improvements

- New detection rules

- Feature requests






==================================================

License

==================================================



MIT License






==================================================

Author

==================================================



Created by:


jilejiang10-create



GitHub:


https://github.com/jilejiang10-create/agent-skill-security