// Configuration
const API_BASE_URL = window.location.origin;

// State management
let currentProfiles = [];
let selectedProfileKey = "";
let currentScanData = null;

// DOM Elements
const profileSelect = document.getElementById("profile-select");
const previewName = document.getElementById("preview-name");
const previewDesc = document.getElementById("preview-desc");
const previewHost = document.getElementById("preview-host");
const previewIp = document.getElementById("preview-ip");
const scanBtn = document.getElementById("scan-btn");

// Agent Nodes
const nodeRecon = document.getElementById("node-recon");
const nodeVuln = document.getElementById("node-vulnerability");
const nodeRisk = document.getElementById("node-risk");
const nodeReport = document.getElementById("node-report");

const connector1 = document.getElementById("connector-1");
const connector2 = document.getElementById("connector-2");
const connector3 = document.getElementById("connector-3");

// Terminal logs
const terminalLogs = document.getElementById("terminal-logs");

// Report elements
const reportEmptyState = document.getElementById("report-empty-state");
const reportActiveState = document.getElementById("report-active-state");
const reportRiskBadge = document.getElementById("report-risk-badge");
const reportCveCount = document.getElementById("report-cve-count");
const portsTableBody = document.querySelector("#ports-table tbody");
const executiveSummaryContent = document.getElementById("executive-summary-content");
const vulnerabilitiesList = document.getElementById("vulnerabilities-list");

const copyMarkdownBtn = document.getElementById("copy-markdown-btn");
const downloadReportBtn = document.getElementById("download-report-btn");
const printReportBtn = document.getElementById("print-report-btn");

const topologyContainer = document.getElementById("topology-container");
const threatIntelContainer = document.getElementById("threat-intel-container");
const remediationTrackerList = document.getElementById("remediation-tracker-list");
const remediationProgressBar = document.getElementById('remediation-progress-bar');
const remediationScore = document.getElementById('remediation-score');
const fullReconContainer = document.getElementById('full-recon-container');


// Initialize page
document.addEventListener("DOMContentLoaded", async () => {
    setupTabs();
    await loadProfiles();
    
    // Scan Button handler
    scanBtn.addEventListener("click", () => {
        if (selectedProfileKey) {
            runScanPipeline(selectedProfileKey);
        }
    });

    // Copy / Download handlers
    copyMarkdownBtn.addEventListener("click", copyReportMarkdown);
    downloadReportBtn.addEventListener("click", downloadReportMarkdown);
    printReportBtn.addEventListener("click", () => window.print());
});

// Load profiles from backend API
async function loadProfiles() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/profiles`);
        if (!response.ok) throw new Error("Failed to fetch profiles");
        
        const data = await response.json();
        currentProfiles = data.profiles;
        
        // Populate select element
        profileSelect.innerHTML = "";
        currentProfiles.forEach(profile => {
            const option = document.createElement("option");
            option.value = profile.key;
            option.textContent = profile.name;
            profileSelect.appendChild(option);
        });

        // Append custom target option
        const customOption = document.createElement("option");
        customOption.value = "custom";
        customOption.textContent = "Custom Target...";
        profileSelect.appendChild(customOption);

        // Set default selected profile
        if (currentProfiles.length > 0) {
            updateProfileSelection(currentProfiles[0].key);
        }

        // Add change listener
        profileSelect.addEventListener("change", (e) => {
            updateProfileSelection(e.target.value);
        });

    } catch (error) {
        console.error("Error loading profiles:", error);
        logToTerminal(`[SYSTEM ERROR] Failed to connect to backend: ${error.message}`, "vuln-line");
    }
}

// Update profile card details on change
function updateProfileSelection(key) {
    selectedProfileKey = key;
    const previewCard = document.getElementById("company-preview-card");
    const customInputs = document.getElementById("custom-target-inputs");
    
    if (key === "custom") {
        if (previewCard) previewCard.classList.add("hidden");
        if (customInputs) customInputs.classList.remove("hidden");
    } else {
        if (previewCard) previewCard.classList.remove("hidden");
        if (customInputs) customInputs.classList.add("hidden");
        const profile = currentProfiles.find(p => p.key === key);
        if (profile) {
            previewName.textContent = profile.name;
            previewDesc.textContent = profile.description;
            previewHost.textContent = profile.target;
            previewIp.textContent = profile.ip;
        }
    }
}

// Terminal log helper
function logToTerminal(message, className = "system-line") {
    const line = document.createElement("div");
    line.className = `log-line ${className}`;
    
    // Add current timestamp
    const now = new Date();
    const timeStr = now.toTimeString().split(" ")[0];
    line.textContent = `[${timeStr}] ${message}`;
    
    terminalLogs.appendChild(line);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
}

// Clear terminal logs
function clearTerminal() {
    terminalLogs.innerHTML = "";
}

// Tabs setup
function setupTabs() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            // Remove active classes
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.remove("active"));
            
            // Add active class to clicked tab
            tab.classList.add("active");
            
            // Show corresponding pane
            const targetId = tab.dataset.tab;
            document.getElementById(targetId).classList.add("active");
        });
    });
}

// Trigger multi-agent scanner
async function runScanPipeline(key) {
    // UI Updates - Disable buttons and reset nodes
    scanBtn.disabled = true;
    scanBtn.querySelector(".btn-text").textContent = "SCAN IN PROGRESS...";
    
    copyMarkdownBtn.disabled = true;
    downloadReportBtn.disabled = true;
    
    resetAgentNodes();
    clearTerminal();
    
    try {
        let scanPromise;
        let targetText = previewHost.textContent;

        if (key === "custom") {
            const nameVal = document.getElementById("custom-name").value.trim() || "Custom Target";
            const hostVal = document.getElementById("custom-host").value.trim() || "custom.host";
            const ipVal = document.getElementById("custom-ip").value.trim() || "127.0.0.1";
            const descVal = document.getElementById("custom-desc").value.trim() || "Custom dynamic target scan.";
            
            if (!/^[a-zA-Z0-9.-]+$/.test(hostVal)) {
                throw new Error("Invalid characters in target domain/host");
            }
            if (!/^[0-9.:a-fA-F]+$/.test(ipVal)) {
                throw new Error("Invalid IP address format");
            }
            
            const portCheckboxes = document.querySelectorAll(".port-checkbox:checked");
            const portsVal = Array.from(portCheckboxes).map(cb => parseInt(cb.value));
            
            targetText = hostVal;
            previewHost.textContent = hostVal;
            previewIp.textContent = ipVal;
            
            scanPromise = fetch(`${API_BASE_URL}/api/scan/custom`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    name: nameVal,
                    description: descVal,
                    target: hostVal,
                    ip: ipVal,
                    ports: portsVal
                })
            }).then(res => {
                if (!res.ok) throw new Error("Scan API returned error status");
                return res.json();
            });
        } else {
            scanPromise = fetch(`${API_BASE_URL}/api/scan/${key}`).then(res => {
                if (!res.ok) throw new Error("Scan API returned error status");
                return res.json();
            });
        }

        logToTerminal(`[ORCHESTRATOR] Starting Sentinel Threat pipeline for target: ${targetText}`, "system-line");

        // Stage 1: Recon Agent Animation
        setAgentState("recon", "running");
        logToTerminal("[RECON] Launching outside-in asset reconnaissance scan...", "recon-line");
        logToTerminal(`[RECON] Mapping ports, DNS records and querying public Shodan intelligence databases for: ${previewHost.textContent}...`, "recon-line");
        
        await sleep(1500); // UI visual transition
        
        // Wait for scan to complete or continue simulating steps
        const data = await scanPromise;
        currentScanData = data.results;
        
        // Recon Complete
        const reconData = currentScanData.recon.data;
        logToTerminal(`[RECON] Finished target identification. Host IP resolved: ${reconData.ip}.`, "recon-line");
        logToTerminal(`[RECON] Exposed Ports Discovered: ${reconData.ports.map(p => p.port + "/" + p.service).join(", ")}`, "recon-line");
        setAgentState("recon", "success");
        connector1.classList.add("active");

        // Stage 2: Vulnerability Agent Animation
        setAgentState("vuln", "running");
        logToTerminal("[VULN] Commencing service banner CVE checks and software version verification...", "vuln-line");
        logToTerminal(`[VULN] Querying local vulnerability intelligence engine for exposed services: ${reconData.ports.map(p => p.product).filter(Boolean).join(", ")}`, "vuln-line");
        
        await sleep(1500);
        
        const vulns = currentScanData.vulnerability.data;
        logToTerminal(`[VULN] Analysis finished. Detected ${vulns.length} service/configuration vulnerability vectors.`, "vuln-line");
        vulns.forEach(v => {
            logToTerminal(`[VULN ALERT] Found ${v.severity} vulnerability on port ${v.port} (${v.cve}): ${v.title}`, "vuln-line");
        });
        setAgentState("vuln", "success");
        connector2.classList.add("active");

        // Stage 3: Risk Analysis Agent (Gemini)
        setAgentState("risk", "running");
        logToTerminal("[RISK] Running risk matrix calculations and calculating business operational impact...", "risk-line");
        logToTerminal("[RISK] Sending context model telemetry and vulnerability payloads to Gemini AI parser...", "risk-line");
        
        await sleep(1500);
        
        const riskData = currentScanData.risk.data;
        logToTerminal(`[RISK] Analysis complete. Overall Threat Level evaluated as: ${riskData.risk_level}`, "risk-line");
        logToTerminal(`[RISK] Primary business impact evaluated: ${riskData.business_impact.substring(0, 80)}...`, "risk-line");
        setAgentState("risk", "success");
        connector3.classList.add("active");

        // Stage 4: Report Generation Agent (Gemini)
        setAgentState("report", "running");
        logToTerminal("[REPORT] Drafting client remediation checklist and compiling threat document...", "report-line");
        logToTerminal("[REPORT] Formatting details and converting risk tables to Markdown document...", "report-line");
        
        await sleep(1200);
        
        const reportData = currentScanData.report.data;
        logToTerminal("[REPORT] Document generation finalized.", "report-line");
        setAgentState("report", "success");
        
        // Finalize Pipeline UI
        logToTerminal(`[ORCHESTRATOR] Multi-agent assessment successfully completed for ${data.company_name}.`, "system-line");
        
        // Render findings to dashboard
        renderReport(data);
        
        // Enable action buttons
        copyMarkdownBtn.disabled = false;
        downloadReportBtn.disabled = false;
        printReportBtn.disabled = false;

    } catch (err) {
        console.error(err);
        logToTerminal(`[ORCHESTRATOR ERROR] Pipeline failed: ${err.message}`, "vuln-line");
        // Reset node states to reflect failure
        resetAgentNodes();
    } finally {
        // Reset button
        scanBtn.disabled = false;
        scanBtn.querySelector(".btn-text").textContent = "INITIALIZE MULTI-AGENT SCAN";
    }
}

// Reset node UI states
function resetAgentNodes() {
    const nodes = [nodeRecon, nodeVuln, nodeRisk, nodeReport];
    nodes.forEach(node => {
        node.className = "agent-node";
        node.querySelector(".node-status").textContent = "STANDBY";
    });
    
    const connectors = [connector1, connector2, connector3];
    connectors.forEach(c => c.className = "flow-connector");
}

// Set state of a node
function setAgentState(agent, state) {
    let nodeElement;
    let label = "STANDBY";
    
    if (agent === "recon") {
        nodeElement = nodeRecon;
    } else if (agent === "vuln") {
        nodeElement = nodeVuln;
    } else if (agent === "risk") {
        nodeElement = nodeRisk;
    } else if (agent === "report") {
        nodeElement = nodeReport;
    }
    
    if (state === "running") {
        label = "RUNNING";
    } else if (state === "success") {
        label = "COMPLETE";
    }
    
    if (nodeElement) {
        nodeElement.className = `agent-node ${state}`;
        nodeElement.querySelector(".node-status").textContent = label;
    }
}

// Sleep helper
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Render report components
function renderReport(data) {
    reportEmptyState.classList.add("hidden");
    reportActiveState.classList.remove("hidden");
    
    const results = data.results;
    
    // Risk Rating Badge
    const riskLevel = results.risk.data.risk_level;
    reportRiskBadge.textContent = riskLevel;
    reportRiskBadge.className = `stat-value ${riskLevel}`;
    
    // CVE Count
    const cvesCount = results.vulnerability.data.length;
    reportCveCount.textContent = cvesCount;
    
    // Exposed Ports Table
    portsTableBody.innerHTML = "";
    results.recon.data.ports.forEach(port => {
        const row = document.createElement("tr");
        
        row.innerHTML = `
            <td>${port.port}</td>
            <td>${port.service}</td>
            <td>${port.product || "Unknown"} ${port.version || ""}</td>
            <td><span class="port-status-pill">${port.state.toUpperCase()}</span></td>
        `;
        
        portsTableBody.appendChild(row);
    });
    
    // Render Markdown Report
    const mdContent = results.report.data.report_markdown;
    executiveSummaryContent.innerHTML = parseMarkdownToHTML(mdContent);
    
    // Render Vulnerability Cards
    vulnerabilitiesList.innerHTML = "";
    results.vulnerability.data.forEach(vuln => {
        const card = document.createElement("div");
        card.className = `vuln-card ${vuln.severity}`;
        
        card.innerHTML = `
            <div class="vuln-card-header">
                <span class="vuln-card-title">${vuln.title}</span>
                <span class="vuln-badge ${vuln.severity}">${vuln.severity}</span>
            </div>
            <div class="vuln-metadata">
                <span><i class="fa-solid fa-code"></i>ID: ${vuln.cve || vuln.id}</span>
                <span><i class="fa-solid fa-network-wired"></i>Port: ${vuln.port}/${vuln.service}</span>
            </div>
            <p class="vuln-desc">${vuln.description}</p>
            <div class="vuln-remediation">
                <strong><i class="fa-solid fa-circle-check"></i> Remediation:</strong> ${vuln.remediation}
            </div>
        `;
        
        vulnerabilitiesList.appendChild(card);
    });

    // Render Threat Intel
    renderThreatIntel(results.recon.data);
    
    // Render Topology
    renderTopology(results.recon.data);
    
    // Render Remediation Tracker
    renderRemediationTracker(results.vulnerability.data);

    // Render Full Recon Report (14 sections)
    if (data.comprehensive_recon) {
        renderFullReconReport(data);
    }
}

// Simple markdown-to-HTML parser for dynamic rendering
function parseMarkdownToHTML(md) {
    if (!md) return "";
    
    const lines = md.split('\n');
    let html = '';
    let inList = false;
    
    for (let line of lines) {
        let trimmed = line.trim();
        
        // Headers
        if (trimmed.startsWith('# ')) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h1>${parseInlineMarkdown(trimmed.substring(2))}</h1>`;
        } else if (trimmed.startsWith('## ')) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h2>${parseInlineMarkdown(trimmed.substring(3))}</h2>`;
        } else if (trimmed.startsWith('### ')) {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<h3>${parseInlineMarkdown(trimmed.substring(4))}</h3>`;
        }
        // Bullet lists
        else if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
            if (!inList) { html += '<ul>'; inList = true; }
            const content = trimmed.substring(2);
            html += `<li>${parseInlineMarkdown(content)}</li>`;
        }
        // Ordered lists
        else if (/^\d+\.\s/.test(trimmed)) {
            if (inList) { html += '</ul>'; inList = false; }
            const num = trimmed.match(/^\d+/)[0];
            const content = trimmed.replace(/^\d+\.\s+/, '');
            html += `<p><strong>${num}.</strong> ${parseInlineMarkdown(content)}</p>`;
        }
        // Empty lines
        else if (trimmed === '') {
            if (inList) { html += '</ul>'; inList = false; }
        }
        // Regular paragraphs
        else {
            if (inList) { html += '</ul>'; inList = false; }
            html += `<p>${parseInlineMarkdown(trimmed)}</p>`;
        }
    }
    
    if (inList) { html += '</ul>'; }
    return html;
}

function parseInlineMarkdown(text) {
    return text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>');
}

// Copy Markdown to Clipboard
function copyReportMarkdown() {
    if (!currentScanData) return;
    
    const md = currentScanData.report.data.report_markdown;
    navigator.clipboard.writeText(md).then(() => {
        logToTerminal("[SYSTEM] Report Markdown successfully copied to clipboard.", "system-line");
        alert("Markdown report copied to clipboard!");
    }).catch(err => {
        console.error("Could not copy report: ", err);
    });
}

// Download Markdown Report File
function downloadReportMarkdown() {
    if (!currentScanData) return;
    
    const md = currentScanData.report.data.report_markdown;
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement("a");
    a.href = url;
    a.download = `Sentinel_Report_${selectedProfileKey}_${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(a);
    a.click();
    
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    logToTerminal("[SYSTEM] Report Markdown file downloaded.", "system-line");
}

function renderThreatIntel(reconData) {
    const dns = reconData.dns_records || {};
    const intel = reconData.threat_intel || {};
    
    threatIntelContainer.innerHTML = `
        <div class="intel-card">
            <h4>DNS & Routing</h4>
            <div class="intel-data-row"><span class="intel-data-label">A Record</span><span class="intel-data-value">${dns.A || "N/A"}</span></div>
            <div class="intel-data-row"><span class="intel-data-label">MX Record</span><span class="intel-data-value">${dns.MX || "N/A"}</span></div>
            <div class="intel-data-row"><span class="intel-data-label">ISP/ASN</span><span class="intel-data-value">${reconData.isp || "Unknown"}</span></div>
            <div class="intel-data-row"><span class="intel-data-label">Location</span><span class="intel-data-value">${reconData.geo || "Unknown"}</span></div>
        </div>
        <div class="intel-card">
            <h4>Email Security</h4>
            <div class="intel-data-row"><span class="intel-data-label">SPF Policy</span><span class="intel-data-value">${dns.SPF || "Not Enforced"}</span></div>
            <div class="intel-data-row"><span class="intel-data-label">DMARC Policy</span><span class="intel-data-value">${dns.DMARC || "Missing"}</span></div>
        </div>
        <div class="intel-card">
            <h4>Threat Feed</h4>
            <div class="intel-data-row"><span class="intel-data-label">Malware Score</span><span class="intel-data-value">${intel.malware_score || "N/A"}</span></div>
            <div class="intel-data-row"><span class="intel-data-label">Botnet Activity</span><span class="intel-data-value">${intel.known_botnet ? "DETECTED" : "None"}</span></div>
            <div class="intel-data-row"><span class="intel-data-label">Spam Blocklist</span><span class="intel-data-value">${intel.spam_blocklist || "Clean"}</span></div>
        </div>
    `;
}

function renderTopology(reconData) {
    const ports = reconData.ports || [];
    let svgNodes = '';
    let svgLinks = '';
    
    // Center node (Target)
    const centerX = 200;
    const centerY = 200;
    
    svgNodes += `
        <g class="topology-node">
            <circle cx="${centerX}" cy="${centerY}" r="25" />
            <text x="${centerX}" y="${centerY + 40}">${reconData.target || 'Target'}</text>
        </g>
    `;
    
    // Surrounding nodes (Ports/Services)
    const radius = 110;
    ports.forEach((port, index) => {
        const angle = (index / Math.max(ports.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const x = centerX + radius * Math.cos(angle);
        const y = centerY + radius * Math.sin(angle);
        
        let severityClass = 'low';
        if ([21, 22, 23, 3389, 445].includes(port.port)) severityClass = 'critical';
        else if ([8080, 3306, 6379].includes(port.port)) severityClass = 'high';
        
        svgLinks += `<line class="topology-link" x1="${centerX}" y1="${centerY}" x2="${x}" y2="${y}" />`;
        svgNodes += `
            <g class="topology-node ${severityClass}">
                <circle cx="${x}" cy="${y}" r="18" />
                <text x="${x}" y="${y - 22}">${port.port}</text>
                <text x="${x}" y="${y - 10}" style="font-size:9px;fill:#8a99ad">${port.service}</text>
            </g>
        `;
    });
    
    topologyContainer.innerHTML = `
        <svg width="100%" height="100%" viewBox="0 0 400 400" xmlns="http://www.w3.org/2000/svg">
            ${svgLinks}
            ${svgNodes}
        </svg>
    `;
}

function renderRemediationTracker(vulnerabilities) {
    remediationTrackerList.innerHTML = '';
    
    if (!vulnerabilities || vulnerabilities.length === 0) {
        remediationTrackerList.innerHTML = `<div class="remediation-item done"><div class="remedy-content"><span class="remedy-title">No vulnerabilities detected. Good job!</span></div></div>`;
        updateRemediationScore();
        return;
    }
    
    vulnerabilities.forEach((vuln, idx) => {
        const id = `remedy-${idx}`;
        const item = document.createElement('div');
        item.className = 'remediation-item';
        item.innerHTML = `
            <input type="checkbox" id="${id}" class="cyber-checkbox">
            <div class="remedy-content">
                <label for="${id}" class="remedy-title">Fix ${vuln.cve || vuln.id}: ${vuln.title}</label>
                <span class="remedy-desc">${vuln.remediation}</span>
            </div>
        `;
        
        const checkbox = item.querySelector('input');
        checkbox.addEventListener('change', () => {
            item.classList.toggle('done', checkbox.checked);
            updateRemediationScore();
        });
        
        remediationTrackerList.appendChild(item);
    });
    
    updateRemediationScore();
}

function updateRemediationScore() {
    const checkboxes = document.querySelectorAll('.cyber-checkbox');
    if (checkboxes.length === 0) {
        remediationProgressBar.style.width = '100%';
        remediationScore.textContent = 'Score: 100 / 100';
        return;
    }
    
    const checked = document.querySelectorAll('.cyber-checkbox:checked').length;
    const total = checkboxes.length;
    const percentage = Math.round((checked / total) * 100);
    
    remediationProgressBar.style.width = `${percentage}%`;
    remediationScore.textContent = `Score: ${percentage} / 100`;
}

// ═══════════════════════════════════════════════════
// FULL 14-SECTION RECONNAISSANCE REPORT RENDERER
// ═══════════════════════════════════════════════════

function renderFullReconReport(data) {
    if (!fullReconContainer || !data.comprehensive_recon) return;
    const cr = data.comprehensive_recon;
    const results = data.results;
    const reconData = results.recon.data;
    const vulns = results.vulnerability.data;

    // ── Helpers ──────────────────────────────────────────
    const riskBadge = r => `<span class="risk-tag ${r.toLowerCase()}">${r}</span>`;
    const statusBadge = s => {
        const cls = s === 'Present' || s === 'Pass' ? 'badge-present'
                  : s === 'Unknown' ? 'badge-warning' : 'badge-missing';
        return `<span class="status-badge ${cls}">${s}</span>`;
    };
    const scoreBar = (score, max = 10) => {
        const pct = Math.round((score / max) * 100);
        const color = pct >= 70 ? '#00ff66' : pct >= 40 ? '#ffaa00' : '#ff0055';
        return `<div class="score-bar-container"><div class="score-bar-fill" style="width:${pct}%;background:${color}"></div></div>`;
    };
    const mkTable = (headers, rows) => {
        const th = headers.map(h => `<th>${h}</th>`).join('');
        const td = rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('');
        return `<div class="table-container"><table><thead><tr>${th}</tr></thead><tbody>${td}</tbody></table></div>`;
    };

    // Pre-compute reused values
    const missingHeaders = Object.entries(cr.security_headers)
        .filter(([, v]) => v.status === 'Missing').map(([k]) => k);
    const criticalVulns = vulns.filter(v => v.severity === 'CRITICAL');
    const ssl = cr.ssl_info;
    const es = cr.email_security;
    const sh = cr.shodan_intelligence;
    const ci = cr.cloud_info;
    const ts = cr.tech_stack;
    const as = cr.attack_surface;
    const sb = cr.severity_breakdown;
    const w  = cr.whois;
    const dns = reconData.dns_records || {};

    // ── Section 1: Executive Summary ─────────────────────
    const s1 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-chart-pie"></i> 1. Executive Summary</div>
        <div class="recon-section-body">
            <div class="exec-summary-grid">
                <div class="exec-stat-card"><span class="exec-stat-label">Target Domain</span><span class="exec-stat-value">${reconData.target}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">IP Address</span><span class="exec-stat-value">${reconData.ip}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">Assessment Date</span><span class="exec-stat-value">${cr.assessment_date}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">Overall Risk Rating</span><span class="exec-stat-value">${riskBadge(cr.overall_risk)}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">Total Open Ports</span><span class="exec-stat-value neon-cyan">${cr.total_open_ports}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">Subdomains Found</span><span class="exec-stat-value neon-cyan">${cr.total_subdomains}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">High-Risk Findings</span><span class="exec-stat-value neon-red">${cr.high_risk_findings}</span></div>
                <div class="exec-stat-card"><span class="exec-stat-label">Security Score</span><span class="exec-stat-value neon-cyan">${as.overall_score}/100</span></div>
            </div>
        </div>
    </div>`;

    // ── Section 2: Target Information (WHOIS) ────────────
    const s2 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-id-card"></i> 2. Target Information</div>
        <div class="recon-section-body">
            ${mkTable(['Field','Value'],[
                ['Organization', w.organization],
                ['Registrar', w.registrar],
                ['Registration Date', w.registration_date],
                ['Expiration Date', w.expiration_date],
                ['Name Servers', w.name_servers.join(', ')],
                ['Country', w.country],
                ['Admin Contact', w.contact]
            ])}
        </div>
    </div>`;

    // ── Section 3: DNS Enumeration ────────────────────────
    const s3 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-sitemap"></i> 3. DNS Enumeration</div>
        <div class="recon-section-body">
            ${mkTable(['Record Type','Value'],[
                ['A (IPv4)',    `<span class="neon-cyan">${dns.A || reconData.ip}</span>`],
                ['AAAA (IPv6)', 'Not configured (IPv4 only)'],
                ['MX',         dns.MX || 'Not Found'],
                ['TXT / SPF',  dns.TXT || 'Not Found'],
                ['NS',         `${w.name_servers[0]}, ${w.name_servers[1]}`],
                ['CNAME',      `www.${reconData.target}`]
            ])}
            <div class="recon-findings">
                <div class="findings-title">⚡ DNS Security Findings</div>
                <div class="findings-list">
                    ${es.spf.status === 'Fail'
                        ? '<div class="finding-item finding-high">Missing / Misconfigured SPF — email spoofing risk elevated</div>'
                        : '<div class="finding-item finding-ok">SPF record present and configured</div>'}
                    ${es.dmarc.status === 'Fail'
                        ? '<div class="finding-item finding-high">Missing DMARC policy — no email reject/quarantine enforcement</div>'
                        : '<div class="finding-item finding-ok">DMARC policy enforced</div>'}
                </div>
            </div>
        </div>
    </div>`;

    // ── Section 4: Subdomain Discovery ───────────────────
    const subRows = cr.subdomains.map(s => [
        s.subdomain,
        s.status === 'Active'
            ? '<span class="status-badge badge-present">Active</span>'
            : '<span class="status-badge badge-missing">Inactive</span>',
        s.ip,
        riskBadge(s.risk)
    ]);
    const s4 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-diagram-project"></i> 4. Subdomain Discovery</div>
        <div class="recon-section-body">
            ${mkTable(['Subdomain','Status','IP Address','Risk'], subRows)}
            <div class="recon-findings">
                <div class="findings-title">⚡ Risk Indicators</div>
                <div class="findings-list">
                    <div class="finding-item finding-high">Development environment (dev.*) is publicly accessible</div>
                    <div class="finding-item finding-high">Staging server (staging.*) accessible from internet</div>
                    <div class="finding-item finding-critical">Admin portal (admin.*) detected — authentication audit required</div>
                </div>
            </div>
        </div>
    </div>`;

    // ── Section 5: Technology Stack ───────────────────────
    const s5 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-layer-group"></i> 5. Technology Stack Detection</div>
        <div class="recon-section-body">
            ${mkTable(['Category','Technology'],[
                ['Web Server', ts.web_server],
                ['Framework',  ts.framework],
                ['Backend',    ts.backend],
                ['CMS',        ts.cms],
                ['CDN',        ts.cdn],
                ['Database',   ts.database]
            ])}
            <div class="tech-libs">
                <div class="findings-title">📦 Libraries Detected</div>
                <div class="tech-libs-grid">${ts.libraries.map(l => `<span class="tech-lib-tag">${l}</span>`).join('')}</div>
            </div>
        </div>
    </div>`;

    // ── Section 6: SSL/TLS Analysis ───────────────────────
    const s6 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-lock"></i> 6. SSL / TLS Analysis</div>
        <div class="recon-section-body">
            ${mkTable(['Field','Value'],[
                ['Certificate Issuer', ssl.issuer],
                ['Subject / Domain',   ssl.subject],
                ['Valid From',         ssl.valid_from],
                ['Valid Until',        ssl.valid_until],
                ['Days Until Expiry',  `<span class="${ssl.days_until_expiry < 30 ? 'neon-red' : 'neon-green'}">${ssl.days_until_expiry} days</span>`],
                ['TLS Protocol',       ssl.tls_version],
                ['Weak Ciphers',       ssl.weak_ciphers_detected ? '<span class="status-badge badge-missing">DETECTED</span>' : '<span class="status-badge badge-present">None Found</span>'],
                ['Certificate Valid',  ssl.certificate_valid ? '<span class="status-badge badge-present">Valid</span>' : '<span class="status-badge badge-missing">Expired</span>'],
                ['Expiry Risk',        riskBadge(ssl.expiry_risk)]
            ])}
        </div>
    </div>`;

    // ── Section 7: Open Ports & Services ─────────────────
    const portRows = reconData.ports.map(p => [
        `<span class="neon-cyan">${p.port}</span>`,
        p.service,
        `${p.product || 'Unknown'} ${p.version || ''}`.trim(),
        '<span class="status-badge badge-present">Open</span>'
    ]);
    const s7 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-ethernet"></i> 7. Open Ports &amp; Services</div>
        <div class="recon-section-body">
            ${mkTable(['Port','Service','Product / Banner','Status'], portRows)}
        </div>
    </div>`;

    // ── Section 8: Shodan Intelligence ───────────────────
    const s8 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-satellite-dish"></i> 8. Shodan Intelligence</div>
        <div class="recon-section-body">
            ${mkTable(['Field','Value'],[
                ['Open Services',    sh.open_services],
                ['Geolocation',      sh.geolocation],
                ['ISP / ASN',        sh.isp],
                ['Historical Data',  sh.historical_data],
                ['Exposure Rating',  riskBadge(sh.exposure_rating)],
                ['Shodan Score',     sh.shodan_score]
            ])}
        </div>
    </div>`;

    // ── Section 9: Security Headers ───────────────────────
    const headerRows = Object.entries(cr.security_headers).map(([name, val]) => [
        `<code>${name}</code>`,
        statusBadge(val.status),
        val.risk === 'None' ? '—' : riskBadge(val.risk.toUpperCase())
    ]);
    const s9 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-shield-halved"></i> 9. Security Headers Analysis</div>
        <div class="recon-section-body">
            ${mkTable(['Header','Status','Risk'], headerRows)}
            ${missingHeaders.length ? `
            <div class="recon-findings">
                <div class="findings-title">⚡ Recommendations</div>
                <div class="findings-list">
                    ${missingHeaders.map(h => `<div class="finding-item finding-high">Add <code>${h}</code> to all HTTP responses</div>`).join('')}
                </div>
            </div>` : ''}
        </div>
    </div>`;

    // ── Section 10: Email Security ────────────────────────
    const s10 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-envelope-open-text"></i> 10. Email Security Assessment</div>
        <div class="recon-section-body">
            ${mkTable(['Protocol','Status','Record / Details'],[
                ['SPF',  statusBadge(es.spf.status),  es.spf.record],
                ['DKIM', statusBadge(es.dkim.status), es.dkim.record],
                ['DMARC',statusBadge(es.dmarc.status),es.dmarc.record]
            ])}
            <div class="recon-findings">
                <div class="findings-title">⚡ Risk Assessment</div>
                <div class="findings-list">
                    <div class="finding-item ${es.email_spoofing_risk === 'High' ? 'finding-high' : 'finding-ok'}">Email Spoofing Risk: <strong>${es.email_spoofing_risk}</strong></div>
                    <div class="finding-item ${es.phishing_exposure === 'Elevated' ? 'finding-high' : 'finding-ok'}">Phishing Exposure: <strong>${es.phishing_exposure}</strong></div>
                </div>
            </div>
        </div>
    </div>`;

    // ── Section 11: Cloud & Infrastructure ───────────────
    const s11 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-cloud"></i> 11. Cloud &amp; Infrastructure Discovery</div>
        <div class="recon-section-body">
            ${mkTable(['Category','Value'],[
                ['Hosting Provider',  ci.provider],
                ['CDN Detected',      ci.cdn],
                ['Exposure Rating',   riskBadge(ci.exposure_rating)],
                ['Storage Exposure',  ci.storage_exposure.length ? ci.storage_exposure.join(', ') : 'None Detected']
            ])}
        </div>
    </div>`;

    // ── Section 12: Vulnerability Intelligence ────────────
    const cveRows = vulns.map(v => [
        `<span class="neon-cyan">${v.port}/${v.service}</span>`,
        v.product || 'Unknown',
        v.version || 'Unknown',
        `<code>${v.cve || v.id}</code>`,
        riskBadge(v.severity)
    ]);
    const s12 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-bug"></i> 12. Vulnerability Intelligence</div>
        <div class="recon-section-body">
            ${mkTable(['Service','Product','Version','CVE / ID','Severity'], cveRows)}
            <div class="findings-title" style="margin-top:4px">📊 Severity Breakdown</div>
            ${mkTable(['Severity','Count'],[
                [riskBadge('CRITICAL'), sb.CRITICAL],
                [riskBadge('HIGH'),     sb.HIGH],
                [riskBadge('MEDIUM'),   sb.MEDIUM],
                [riskBadge('LOW'),      sb.LOW]
            ])}
        </div>
    </div>`;

    // ── Section 13: Attack Surface Score ─────────────────
    const ringColor = as.overall_score >= 70 ? '#00ff66' : as.overall_score >= 40 ? '#ffaa00' : '#ff0055';
    const ringGlow  = as.overall_score >= 70 ? 'rgba(0,255,102,0.3)' : as.overall_score >= 40 ? 'rgba(255,170,0,0.3)' : 'rgba(255,0,85,0.3)';
    const scoreMsg  = as.overall_score >= 70
        ? 'Good security posture — some areas still need attention.'
        : as.overall_score >= 40
        ? 'Moderate posture — immediate remediation required on critical findings.'
        : 'Poor posture — critical vulnerabilities demand urgent action.';
    const s13 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-gauge-high"></i> 13. Attack Surface Score</div>
        <div class="recon-section-body">
            <div class="attack-surface-grid">
                ${[['DNS Security', as.dns_security], ['SSL Security', as.ssl_security], ['Web Security', as.web_security], ['Exposure Risk', as.exposure_risk]]
                    .map(([label, score]) => `
                    <div class="attack-surface-item">
                        <div class="attack-surface-label">${label}</div>
                        <div class="attack-surface-score-row">
                            ${scoreBar(score)}
                            <span class="attack-surface-value">${score}/10</span>
                        </div>
                    </div>`).join('')}
            </div>
            <div class="overall-score-display">
                <div class="overall-score-ring" style="--ring-color:${ringColor};--ring-glow:${ringGlow}">
                    <span class="overall-score-number">${as.overall_score}</span>
                    <span class="overall-score-label">/ 100</span>
                </div>
                <div class="overall-score-text">
                    <h3>Overall Security Score</h3>
                    <p>${scoreMsg}</p>
                </div>
            </div>
        </div>
    </div>`;

    // ── Section 14: Recommendations ──────────────────────
    const recs = results.risk.data.priority_remediations || [];
    const s14 = `<div class="recon-section">
        <div class="recon-section-header"><i class="fa-solid fa-list-check"></i> 14. Recommendations</div>
        <div class="recon-section-body">
            <div class="recommendations-grid">
                <div class="rec-category">
                    <div class="rec-category-title critical-title"><i class="fa-solid fa-circle-exclamation"></i> Critical</div>
                    <div class="rec-list">
                        ${criticalVulns.length
                            ? criticalVulns.map(v => `<div class="rec-item rec-critical">Patch ${v.cve || v.id}: ${v.title}</div>`).join('')
                            : '<div class="rec-item rec-ok">No critical vulnerabilities detected</div>'}
                        <div class="rec-item rec-critical">Disable all unused public-facing ports immediately</div>
                    </div>
                </div>
                <div class="rec-category">
                    <div class="rec-category-title high-title"><i class="fa-solid fa-triangle-exclamation"></i> High</div>
                    <div class="rec-list">
                        ${missingHeaders.includes('Content-Security-Policy') ? '<div class="rec-item rec-high">Implement Content-Security-Policy header</div>' : ''}
                        ${es.dmarc.status === 'Fail' ? '<div class="rec-item rec-high">Configure DMARC policy to quarantine/reject</div>' : ''}
                        ${ssl.weak_ciphers_detected ? '<div class="rec-item rec-high">Disable weak TLS ciphers; enforce TLS 1.2+</div>' : ''}
                        <div class="rec-item rec-high">Restrict dev/staging subdomains from public internet</div>
                    </div>
                </div>
                <div class="rec-category">
                    <div class="rec-category-title medium-title"><i class="fa-solid fa-circle-info"></i> Medium</div>
                    <div class="rec-list">
                        ${ssl.days_until_expiry < 30 ? '<div class="rec-item rec-medium">Renew SSL certificate — expiring soon</div>' : ''}
                        <div class="rec-item rec-medium">Hide server version banners from HTTP responses</div>
                        <div class="rec-item rec-medium">Enforce HTTP Strict Transport Security (HSTS)</div>
                    </div>
                </div>
            </div>
            ${recs.length ? `
            <div class="findings-title" style="margin-top:16px">🤖 AI Risk Analysis — Priority Actions</div>
            <div class="findings-list">
                ${recs.map((r, i) => `<div class="finding-item finding-high"><strong>${i+1}.</strong> ${r}</div>`).join('')}
            </div>` : ''}
        </div>
    </div>`;

    fullReconContainer.innerHTML = s1+s2+s3+s4+s5+s6+s7+s8+s9+s10+s11+s12+s13+s14;
}
