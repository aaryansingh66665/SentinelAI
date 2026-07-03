# SentinelAI - Enterprise Multi-Agent Threat Intelligence & Security Scanner

[![Online Deployment](https://img.shields.io/badge/Online-Deployed-success?style=for-the-badge&logo=vercel)](https://sentinel-ai-kappa-teal.vercel.app/)

SentinelAI is an advanced, modular, multi-agent cybersecurity scanning and analysis assistant. Leveraging a custom **Agent Development Kit (ADK)**, SentinelAI sequences autonomous AI agents to perform host reconnaissance, match exposures to known CVEs, assess business threat risks, and compile professional executive reports.

SentinelAI is built for adaptability, offering a premium Glassmorphic Web UI, a command-line interface (CLI), and a Model Context Protocol (MCP) Server to expose target scans directly to agentic workflows.

---

## 🌐 Online Use

Want to try SentinelAI immediately without any local setup? Use our hosted online version:

🔗 **[SentinelAI Web Dashboard](https://sentinel-ai-kappa-teal.vercel.app/)**

---

## 🚀 Key Features

* **Multi-Agent Pipeline**: Sequentially triggers **Recon**, **Vulnerability**, **Risk Analysis**, and **Reporting** agents to coordinate a complete security posture scan.
* **FastMCP Server Integration**: Expose `run_security_scan` and `run_custom_security_scan` directly to MCP clients (like Claude Desktop or Gemini IDEs).
* **Hardened Security**:
  * **Input Validation**: Strict validation checking target domain syntax, IP formats, and port lists to prevent script and command injection.
  * **Rate Limiting**: Custom `TokenBucketRateLimiter` protecting API routes from exhaustion and abuse.
  * **Credential Encryption**: AES-256 password-based key encryption for storing API keys securely inside `.env.enc`.
* **Flexible UI / CLI / MCP Interface**: Initiate scans via the premium browser dashboard, terminal commands, or through your favorite MCP host.
* **Automated Mock Profiles & Live Scanning**: Test with predefined mock business profiles, or run live custom network socket and banner grabbing scans.

---

## 🛠️ Technology Stack

SentinelAI is built using a modern, robust, and scalable technology stack:

* **Languages**: Python (Backend/AI Agents), JavaScript (Frontend Dashboard), HTML5, CSS3
* **Backend Framework**: Python 3, FastAPI, Uvicorn (ASGI)
* **Core Packages**: `google-generativeai`, `mcp`, `pydantic`, `cryptography`, `requests`, `dnspython`
* **AI & LLM Integration**: Google Generative AI (Gemini), MCP (Model Context Protocol)
* **Security & Cryptography**: Python `cryptography` module (PBKDF2HMAC, AES-256-GCM)
* **Network Scanning**: Custom socket implementations, DNSPython
* **Frontend UI**: Vanilla JavaScript, HTML5, CSS3 (Glassmorphism design, no heavy frameworks)
* **Containerization**: Docker, Docker Compose

---

## 📊 System Architecture & Working Flowchart

### 1. Working Flowchart
The following diagram illustrates the workflow of the multi-agent scanning pipeline:

```mermaid
graph TD
    User([User / Security Analyst]) -->|Initiates Scan| API[FastAPI Server]
    API --> Limit[Rate Limiter & Input Validation]
    Limit -->|Validated Request| Scanner[Live Network Scanner]
    
    Scanner -.->|Port / Banner / DNS| Target[Target Domain / IP]
    Scanner -->|Raw Data| Pipeline[Agent Pipeline]
    
    subgraph Multi-Agent ADK Pipeline
        Pipeline --> ReconAgent[1. Reconnaissance Agent]
        ReconAgent --> VulnAgent[2. Vulnerability Agent]
        VulnAgent --> RiskAgent[3. Risk Analysis Agent]
        RiskAgent --> ReportAgent[4. Report Generation Agent]
    end
    
    ReportAgent -->|Structured JSON & Markdown| API
    API -->|Displays Results| User
```

### 2. UML Component Diagram
This diagram outlines the core components and their relationships:

```mermaid
classDiagram
    class FastAPI {
        +app.py
        +REST API Endpoints
        +Serve Static Frontend()
    }
    class AgentPipeline {
        +run_recon_agent()
        +run_vulnerability_agent()
        +run_risk_analysis_agent()
        +run_report_agent()
    }
    class ADK {
        +Agent
        +Task
        +Workflow
    }
    class SecurityUtils {
        +encrypt_data(data, password)
        +decrypt_data(payload, password)
        +validate_target(domain)
        +validate_ip(ip)
        +TokenBucketRateLimiter
    }
    class NetworkScanner {
        +full_recon_scan(ip, ports)
        +get_service_name(port)
    }
    
    FastAPI --> AgentPipeline : Triggers scan request
    AgentPipeline --> ADK : Implements Agents & Tasks
    FastAPI --> SecurityUtils : Validates inputs & rate limits
    AgentPipeline --> SecurityUtils : Decrypts LLM API Keys
    AgentPipeline --> NetworkScanner : Fetches live socket data
```

---

## 🔌 Offline Deployment & Installation

You can deploy SentinelAI completely offline or locally on your own machine. 

### Method 1: Docker (Recommended)
SentinelAI can be easily deployed in isolated containers. Ensure you have Docker and Docker Compose installed.

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/SentinelAI.git
   cd SentinelAI
   ```
2. **Set your Gemini API Key in `docker-compose.yml`** or export it to your environment.
3. **Build and Run**:
   ```bash
   docker-compose up --build -d
   ```
4. Access the offline web interface at `http://localhost:8000`.

### Method 2: Manual Python Setup (Windows/Linux/macOS)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/SentinelAI.git
   cd SentinelAI
   ```

2. **Create and Activate a Virtual Environment**:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Where to Insert Your Gemini API Key**:
   You must provide a valid Google Gemini API Key for the AI Agents to function. You can provide it in two ways:
   * **Option A (Environment Variable)**: Create a `.env` file in the root directory and add:
     ```env
     GEMINI_API_KEY=your_api_key_here
     ```
   * **Option B (Secure Encrypted Storage)**: Use the built-in CLI to securely encrypt and store your key in a `.env.enc` file:
     ```bash
     python backend/cli.py set-key
     ```
     *(You will be prompted to enter your API key and a secure decryption password).*

5. **Start the FastAPI Web Server**:
   ```bash
   # Make sure DECRYPTION_PASSWORD is set in your environment if you encrypted your key
   python app.py
   ```
6. Open your browser and navigate to `http://127.0.0.1:8000`.

---

## 💻 CLI & Standalone Usage

You can also run scans directly from your terminal using the offline CLI tool:

**Run a scan against a mock profile:**
```bash
python backend/cli.py scan --profile ecommerce
```

**Run a scan and export the executive report to markdown:**
```bash
python backend/cli.py scan --profile clinic --output report.md
```

---

## 📈 How to Analyze Results & Use the Intelligence

Once a scan completes (either via the Web Dashboard or CLI), SentinelAI outputs a **Comprehensive Executive Report** structured into four distinct AI-analyzed layers. Here is a detailed breakdown of what to look for and how to use this intelligence:

### 1. Reconnaissance Data (The Attack Surface)
* **What it is**: The raw output of live network socket connections, banner grabs, and DNS lookups.
* **Important Things to Look For**: 
  * Unnecessary exposed ports (e.g., `3389 RDP`, `23 Telnet`, or `3306 MySQL`) facing the public internet.
  * Expiring or outdated SSL/TLS certificates (e.g., TLS 1.0/1.1).
  * Missing critical DNS security records like DMARC or SPF.
* **How to use it**: Use this data to immediately restrict firewall rules, close unused ports, and update external DNS routing configurations.

### 2. Vulnerability Mapping (The Weaknesses)
* **What it is**: The AI matches detected services and banners to known CVEs (Common Vulnerabilities and Exposures) and severe misconfigurations.
* **Important Things to Look For**:
  * **Critical & High Severity CVEs**: Vulnerabilities allowing Remote Code Execution (RCE) or unauthenticated data access.
  * Known vulnerable software versions (e.g., an outdated Apache server).
* **How to use it**: Prioritize patching systems highlighted here. The AI provides explicit **Remediation steps** for each vulnerability, which you can hand directly to DevOps or IT engineering teams for mitigation.

### 3. Business Risk Analysis (The Context)
* **What it is**: Contextualized threat modeling. The Risk Analysis agent cross-references the vulnerabilities against the *type* of business (e.g., E-commerce vs. Dental Clinic).
* **Important Things to Look For**:
  * The **Risk Level**: An exposed database port might be "Medium" risk on a dev server, but "Critical" risk on a clinic storing PHI (Protected Health Information).
  * **Business Impact**: How the vulnerabilities directly threaten revenue, compliance (HIPAA, PCI-DSS), or reputation.
* **How to use it**: Use this section to triage and justify security budgets or immediate emergency downtime to management. It translates technical jargon into business impact.

### 4. Executive Summary Report (The Deliverable)
* **What it is**: A finalized, professional Markdown report synthesizing the entire pipeline.
* **How to use it**: 
  * **Via Dashboard**: Review the summarized metrics (Overall Risk Score, Attack Surface Score) visually.
  * **Via CLI**: Run the scan with the `--output report.md` flag. You can export this markdown file into a PDF or hand it directly to non-technical stakeholders, clients, or C-Suite executives to provide a clear, actionable security posture overview.

---

## 📜 License
This project is licensed under a [Personal Use Only License](LICENSE).
