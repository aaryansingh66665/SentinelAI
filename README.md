# SentinelAI - Enterprise Multi-Agent Threat Intelligence & Security Scanner

SentinelAI is an advanced, modular, multi-agent cybersecurity scanning and analysis assistant. Leveraging a custom **Agent Development Kit (ADK)**, SentinelAI sequences autonomous AI agents to perform host reconnaissance, match exposures to known CVEs, assess business threat risks, and compile professional executive reports.

SentinelAI is built for adaptability, offering a **FastFast FastAPI Web UI Dashboard**, a command-line interface (**CLI**), and a **Model Context Protocol (MCP) Server** to expose target scans directly to agentic workflows.

---

## 🏗️ Architecture Layout

The repository is organized following clean, modular design principles:

```
SentinelAI/
├── README.md              # Project documentation and guide
├── requirements.txt       # Python dependencies
├── app.py                 # FastAPI application server (and static host)
├── agents/                # Core Agent Development Kit (ADK) & Agent Pipelines
│   ├── adk.py             # Base Agent, Task, and Workflow definitions
│   └── agents.py          # Security scanner agents definition
├── tools/                 # Utility scanners and security features
│   ├── scanner.py         # Socket-level port scan, banner grabs, and SSL checks
│   └── security.py        # Input sanitization, rate-limiting, and AES-256 encryption
├── mcp/                   # Model Context Protocol (MCP) server
│   └── mcp_server.py      # FastMCP interface exposing tools to LLM ecosystems
├── frontend/              # Glassmorphic dashboard web application
│   ├── index.html         # Threat dashboard front-page layout
│   ├── app.js             # API client, scan animations, and rendering logic
│   └── style.css          # Premium theme styling and glassmorphism elements
├── backend/               # CLI scripts and testing pipelines
│   ├── cli.py             # CLI Command scanner & credential encryptor
│   ├── test_pipeline.py   # Test suite for ADK, security tools, and workflows
│   └── encrypt_key.py     # Script to generate encrypted API key file (.env.enc)
├── docs/                  # Schematic diagrams and documentation assets
│   ├── architecture.png   # System architecture diagram
│   └── workflow.png       # Scanning agent pipeline workflow diagram
├── LICENSE                # MIT License
└── .gitignore             # Git ignore configuration
```

---

## 🚀 Key Features

* **Multi-Agent Pipeline**: Sequentially triggers **Recon**, **Vulnerability**, **Risk Analysis**, and **Reporting** agents to coordinate a complete security posture scan.
* **FastMCP Server**: Run SentinelAI as an MCP server. Expose `run_security_scan` and `run_custom_security_scan` directly to MCP clients (like Claude Desktop or Gemini IDEs).
* **Hardened Security**:
  * **Input Validation**: Hardened validation checking target domain syntax, IP formats, and port lists to prevent script injection.
  * **Rate Limiting**: Custom `TokenBucketRateLimiter` protecting API routes from exhaustion.
  * **Credential Encryption**: AES-256 password-based key encryption for storing API keys securely inside `.env.enc`.
* **Flexible UI / CLI / MCP Interface**: Initiate scans via the premium browser dashboard, terminal commands, or through your favorite MCP host.
* **Easy Deployment**: Fully compatible with Docker and Docker Compose.

---

## 🛠️ Installation & Setup

### Windows Quick-Start
SentinelAI includes a setup batch file that automates environment setup, dependency installs, and starts the FastAPI server:

```powershell
# Run the setup script
.\setup.bat
```

### Manual Installation

1. **Create and Activate a Virtual Environment**:
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix/macOS:
   source venv/bin/activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the FastAPI Web Server**:
   ```bash
   python app.py
   ```
   Open `http://127.0.0.1:8000` in your web browser.

---

## 💻 CLI Usage

The CLI utility handles API key setup and standalone security assessments.

### Set/Encrypt Gemini API Key
To encrypt your API key and store it securely:
```bash
python backend/cli.py set-key
```
Enter your key and set a decryption password when prompted.

### Run a Local Assessment Scan
Perform scans using default mock profiles (`ecommerce`, `clinic`, `accounting`):
```bash
python backend/cli.py scan --profile ecommerce
```
Export findings directly to markdown:
```bash
python backend/cli.py scan --profile clinic --output report.md
```

---

## 🐳 Docker Deployment

SentinelAI can be deployed in containers using the provided configuration:

### Run with Docker Compose
Ensure you set your credentials in the environment or in the docker-compose command:
```bash
docker-compose up --build -d
```
The application will be accessible at `http://localhost:8000`.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
