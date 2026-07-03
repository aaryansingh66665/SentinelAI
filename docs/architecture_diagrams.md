# SentinelAI - Architecture & Flow Diagrams

This document outlines the detailed system architecture, user interactions, data flows, and object-oriented class structure for **SentinelAI** using Mermaid diagrams and rendered PNG images.

---

## 1. Use Case Diagram

The Use Case Diagram shows the interactions between the primary actors (User/Security Analyst, Google Gemini API, and Target Server) and the system.

![Use Case Diagram](use_case_diagram.png)

<details>
<summary>View Mermaid Source</summary>

```mermaid
graph TD
    %% Actors
    User([User / Security Analyst])
    Gemini_API[Google Gemini API]
    Target_Server[Target Host / Domain]

    subgraph SentinelAI System Boundary
        UC1(Initiate Security Scan)
        UC2(Perform Live Network Socket Scan)
        UC3(Run Reconnaissance Agent)
        UC4(Run Vulnerability Assessment Agent)
        UC5(Run Business Risk Analysis Agent)
        UC6(Generate Executive Security Report)
        UC7(Manage Encrypted API Credentials)
        UC8(View Scan History & Dashboard)

        %% Relationships
        UC1 -->|includes| UC2
        UC1 -->|includes| UC3
        UC1 -->|includes| UC4
        UC1 -->|includes| UC5
        UC1 -->|includes| UC6
    end

    User --> UC1
    User --> UC7
    User --> UC8

    UC2 --> Target_Server
    UC3 --> Gemini_API
    UC4 --> Gemini_API
    UC5 --> Gemini_API
    UC6 --> Gemini_API
```
</details>

---

## 2. Data Flow Diagram (DFD)

### Level 0: Context Diagram
A high-level view showing the boundaries of the system and its external entities.

![DFD Level 0 (Context Diagram)](dfd_level0_diagram.png)

<details>
<summary>View Mermaid Source</summary>

```mermaid
graph LR
    User[User / Security Analyst]
    System((SentinelAI System))
    Target[Target Server]
    Gemini[Gemini API]

    User -->|Target Input, API Credentials| System
    System -->|Executive Report, Scan Logs| User
    System -->|Socket Queries / DNS Request| Target
    Target -->|Port Status, Banner Banners| System
    System -->|Raw Scan Data & Prompts| Gemini
    Gemini -->|AI Analysis / Summaries| System
```
</details>

### Level 1: Detailed Data Flow Diagram
A decomposed view showing internal processes, data stores, and data flows.

![DFD Level 1 (Detailed Diagram)](dfd_level1_diagram.png)

<details>
<summary>View Mermaid Source</summary>

```mermaid
graph TD
    %% External Entities
    User[User / Security Analyst]
    Target[Target Server]
    Gemini[Gemini API]

    %% Processes
    P1((P1: Validate Inputs & Rate Limit))
    P2((P2: Perform Live Network Scan))
    P3((P3: Multi-Agent Pipeline))
    P4((P4: Compile Report & Serve))

    %% Data Stores
    DS1[(DS1: Encrypted Credentials .env.enc)]
    DS2[(DS2: Scan Results & Logs)]

    %% Flow lines
    User -->|Target Input & Password| P1
    DS1 -.->|Decryption Keys| P1
    P1 -->|Validated Target| P2
    P2 -->|Socket connection / Banner request| Target
    Target -->|Raw socket data & banners| P2
    P2 -->|Raw Scan Data| P3
    P3 -->|Context Data & Prompts| Gemini
    Gemini -->|AI Analysis & Recommendations| P3
    P3 -->|Agent Reports| P4
    P4 -->|Report Markdown / JSON| DS2
    P4 -->|Dashboard View & Logs| User
    DS2 -.->|Stored Scan Logs| User
```
</details>

---

## 3. UML Diagrams

### UML Class Diagram
The Class Diagram models the object-oriented structure of the backend application, agent orchestrator, and utility subsystems.

![UML Class Diagram](uml_class_diagram.png)

<details>
<summary>View Mermaid Source</summary>

```mermaid
classDiagram
    direction TB
    
    class FastAPI_App {
        +app: FastAPI
        +limiter: TokenBucketRateLimiter
        +run_scan(payload: CustomScanPayload)
        +decrypt_env(password: str)
    }

    class CustomScanPayload {
        +target: str
        +ports: str
        +use_mock: bool
        +password: str
    }

    class TokenBucketRateLimiter {
        -rate: float
        -capacity: float
        -tokens: dict
        -last_update: dict
        -lock: Threading.Lock
        +check_request(client_ip: str) bool
    }

    class SentinelAgentPipeline {
        -target: str
        -raw_scan_data: dict
        -gemini_api_key: str
        -use_mock: bool
        -workflow: Workflow
        +__init__(target, raw_scan_data, gemini_api_key, use_mock)
        +run() dict
    }

    class Workflow {
        +name: str
        +tasks: List~Task~
        +add_task(task: Task)
        +run(initial_context: dict) dict
    }

    class Task {
        +name: str
        +agent: Agent
        +instruction: str
        +input_key: str
        +output_key: str
        +execute(context: dict) dict
    }

    class Agent {
        +name: str
        +role: str
        +system_instruction: str
        +model_name: str
        +api_key: str
        -client: GenerativeModel
        +run(prompt: str, context: dict) dict
    }

    class SecurityUtils {
        <<utility>>
        +encrypt_data(data: bytes, password: str) bytes
        +decrypt_data(payload: bytes, password: str) bytes
        +validate_target(domain: str) bool
        +validate_ip(ip: str) bool
        +validate_ports(ports: str) List~int~
    }

    class NetworkScanner {
        <<utility>>
        +scan_single_port(ip: str, port: int, timeout: float) dict
        +banner_grab(ip: str, port: int, timeout: float) str
        +dns_recon(domain: str) dict
        +full_recon_scan(target: str, ports: List~int~) dict
    }

    FastAPI_App --> CustomScanPayload : Uses
    FastAPI_App --> TokenBucketRateLimiter : Uses
    FastAPI_App --> SecurityUtils : Uses
    FastAPI_App --> SentinelAgentPipeline : Triggers
    SentinelAgentPipeline --> Workflow : Uses
    SentinelAgentPipeline --> NetworkScanner : Uses
    Workflow "1" *-- "many" Task : Composed of
    Task --> Agent : References
```
</details>

### UML Sequence Diagram
The Sequence Diagram traces the end-to-end execution flow of a scanning job.

![UML Sequence Diagram](uml_sequence_diagram.png)

<details>
<summary>View Mermaid Source</summary>

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as User / Analyst
    participant Dashboard as Web Dashboard
    participant API as FastAPI App (app.py)
    participant Scanner as Network Scanner
    participant Pipeline as SentinelAgentPipeline
    participant Workflow as ADK Workflow
    participant Gemini as Google Gemini API

    Analyst->>Dashboard: Input Target & API Passphrase
    Dashboard->>API: POST /api/scan (payload)
    API->>API: Rate limit check (TokenBucketRateLimiter)
    API->>API: Validate target, IP, and ports syntax
    API->>API: Decrypt Gemini API key from .env.enc
    
    alt Live Scan
        API->>Scanner: full_recon_scan(target, ports)
        Scanner->>Scanner: Run multi-threaded socket scan
        Scanner->>Scanner: Perform DNS recon & banner grabbing
        Scanner-->>API: Return raw_scan_data
    else Mock Scan
        API-->>API: Load simulated scan profile
    end

    API->>Pipeline: Create pipeline & run()
    Pipeline->>Workflow: Initialize ADK Workflow with tasks
    
    loop For each Agent Task (Recon, Vuln, Risk, Report)
        Workflow->>Workflow: Get Task input context
        Workflow->>Gemini: generate_content(prompt + context)
        Gemini-->>Workflow: Return analysis / text
        Workflow->>Workflow: Store output in context
    end

    Workflow-->>Pipeline: Return completed context
    Pipeline-->>API: Return finalized threat intelligence JSON
    API-->>Dashboard: Return response (200 OK)
    Dashboard-->>Analyst: Render premium Glassmorphic results & reports
```
</details>
