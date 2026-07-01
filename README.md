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

* **Backend Framework**: Python 3, FastAPI, Uvicorn (ASGI)
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

4. **Set & Encrypt your Gemini API Key**:
   Instead of storing your key in plaintext, SentinelAI provides a CLI to encrypt it locally:
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

## 📜 License
This project is licensed under the [MIT License](LICENSE).
