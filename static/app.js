// State Management
let incidents = [];
let blockedIps = [];
let systemStatus = {};
let selectedIncidentId = null;

// Document Ready
document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

function initApp() {
    // Bind Event Listeners
    document.getElementById("btnRunSimulation").addEventListener("click", runSimulation);
    document.getElementById("btnConfirmRollback").addEventListener("click", confirmRollback);
    
    // Initial fetch calls
    fetchStatus();
    refreshDashboard();
    
    // Auto-refresh state every 30 seconds
    setInterval(() => {
        refreshDashboard();
    }, 30000);
}

// --- API Calls ---

async function fetchStatus() {
    try {
        const response = await fetch("/api/status");
        if (response.ok) {
            systemStatus = await response.json();
            updateStatusIndicator();
        }
    } catch (error) {
        console.error("Failed to fetch system status:", error);
        showToast("Error connecting to server status API.", "error");
    }
}

async function refreshDashboard() {
    try {
        await Promise.all([
            fetchIncidents(),
            fetchBlockedIps()
        ]);
        calculateStats();
    } catch (error) {
        console.error("Dashboard refresh failed:", error);
    }
}

async function fetchIncidents() {
    const tableBody = document.getElementById("incidentsTableBody");
    try {
        const response = await fetch("/api/incidents");
        if (response.ok) {
            incidents = await response.json();
            renderIncidentsTable();
        } else {
            showToast("Failed to fetch incidents list.", "error");
        }
    } catch (error) {
        console.error("Failed to fetch incidents list:", error);
    }
}

async function fetchBlockedIps() {
    try {
        const response = await fetch("/api/firewall/blocks");
        if (response.ok) {
            const data = await response.json();
            blockedIps = data.blocked_ips || [];
            renderBlockedIps();
        }
    } catch (error) {
        console.error("Failed to query blocked IPs:", error);
    }
}

async function runSimulation() {
    const btn = document.getElementById("btnRunSimulation");
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="loader" style="width: 14px; height: 14px; margin-right: 8px; display: inline-block;"></span> Analyzing Logs...`;
    
    try {
        const response = await AppFetch("/api/simulation/run", { method: "POST" });
        if (response && response.success) {
            showToast(response.message, "success");
            await refreshDashboard();
        } else {
            showToast("Simulation execution failed.", "error");
        }
    } catch (error) {
        showToast("Error connecting to simulation service.", "error");
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

// Open Reversal Modal
function triggerRollback(incidentId, ipAddress, event) {
    if (event) event.stopPropagation(); // Avoid opening details modal
    selectedIncidentId = incidentId;
    document.getElementById("rollbackIpAddress").innerText = ipAddress;
    document.getElementById("rollbackReasonSelect").value = "False Positive";
    document.getElementById("rollbackReasonText").value = "";
    toggleCustomReason();
    openModal("modalRollback");
}

async function confirmRollback() {
    const reasonSelect = document.getElementById("rollbackReasonSelect").value;
    let reason = reasonSelect;
    if (reasonSelect === "custom") {
        reason = document.getElementById("rollbackReasonText").value.trim();
        if (!reason) {
            showToast("Please enter a custom rollback reason.", "error");
            return;
        }
    }

    const btn = document.getElementById("btnConfirmRollback");
    btn.disabled = true;
    btn.innerText = "Processing Reversal...";

    try {
        const response = await fetch(`/api/incidents/${selectedIncidentId}/undo`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ reason })
        });
        
        const data = await response.json();
        if (response.ok && data.success) {
            showToast(data.message, "success");
            closeModal("modalRollback");
            await refreshDashboard();
        } else {
            showToast(data.detail || "Rollback execution failed.", "error");
        }
    } catch (error) {
        showToast("Connection error during rollback execution.", "error");
    } finally {
        btn.disabled = false;
        btn.innerText = "Confirm Unblock (Undo)";
    }
}

async function viewIncidentDetail(incidentId) {
    openModal("modalDetail");
    
    // Clear previous details
    document.getElementById("mdId").innerText = "Loading...";
    document.getElementById("mdIp").innerText = "Loading...";
    document.getElementById("mdSeverity").innerText = "Loading...";
    document.getElementById("mdRisk").innerText = "Loading...";
    document.getElementById("mdStatus").innerText = "Loading...";
    document.getElementById("mdAction").innerText = "Loading...";
    document.getElementById("mdClaw").innerText = "Loading...";
    document.getElementById("mdIQ").innerText = "Loading...";
    document.getElementById("mdExplanation").innerText = "Loading explanation details...";
    document.getElementById("mdTimeline").innerHTML = `<div class="loader-container"><div class="loader"></div></div>`;
    document.getElementById("mdCompliance").innerText = "Loading compliance document...";

    try {
        const response = await fetch(`/api/incidents/${incidentId}`);
        if (response.ok) {
            const data = await response.json();
            
            // Populate basic metadata fields (mapping both mock key schemas and backend models)
            document.getElementById("mdId").innerText = incidentId;
            document.getElementById("mdIp").innerText = data.ip_address || data["IP Address"] || "N/A";
            document.getElementById("mdRisk").innerText = `${data.risk_score || data["Risk Score"] || 0}/100`;
            document.getElementById("mdAction").innerText = data.executed_action || data["Executed Action"] || "None";
            
            const severity = data.severity || data["Severity"] || "Low";
            const sevBadge = document.getElementById("mdSeverity");
            sevBadge.innerText = severity;
            sevBadge.className = `badge badge-${severity.toLowerCase()}`;
            
            const status = data.status || data["Status"] || "Pending Approval";
            const statBadge = document.getElementById("mdStatus");
            statBadge.innerText = status;
            statBadge.className = `badge badge-${status.replace(" ", "").toLowerCase()}`;

            // Parse integrations responses
            const clawRes = data.armorclaw_result || parseJsonSafe(data["ArmorClaw Result"]);
            document.getElementById("mdClaw").innerText = clawRes ? `Reputation: ${clawRes.reputation} (Verified: ${clawRes.verified})` : "N/A";
            
            const iqRes = data.armoriq_decision || parseJsonSafe(data["ArmorIQ Decision"]);
            document.getElementById("mdIQ").innerText = iqRes ? `Approved: ${iqRes.approved} (Policy: ${iqRes.policy_name})` : "N/A";

            // Explanation
            document.getElementById("mdExplanation").innerText = data.explanation || "No explanation registered.";

            // Timeline parsing
            renderTimeline(data.timeline || data["Timeline"] || []);

            // Compliance markdown report
            document.getElementById("mdCompliance").innerText = data.compliance_report || data["Compliance Report"] || "No compliance report found.";
        }
    } catch (error) {
        showToast("Error loading incident details.", "error");
        closeModal("modalDetail");
    }
}

// --- Render Operations ---

function updateStatusIndicator() {
    const pulse = document.getElementById("statusPulse");
    const label = document.getElementById("statusLabel");
    
    pulse.className = "status-pulse";
    if (systemStatus.mock_mode) {
        pulse.classList.add("pulse-mock");
        label.innerText = "MOCK MODE ACTIVE";
    } else {
        pulse.classList.add("pulse-live");
        label.innerText = "LIVE API CONNECTED";
    }
}

function renderIncidentsTable() {
    const tbody = document.getElementById("incidentsTableBody");
    const countLabel = document.getElementById("incidentsCount");
    
    if (incidents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No incidents logged in the system. Run simulation to populate.</td></tr>`;
        countLabel.innerText = "0 Incidents";
        return;
    }

    countLabel.innerText = `${incidents.length} Incident${incidents.length === 1 ? '' : 's'}`;
    tbody.innerHTML = "";

    incidents.forEach(inc => {
        const id = inc["Incident ID"] || inc.id;
        const ts = inc["Timestamp"] || inc.timestamp || "";
        const ip = inc["IP Address"] || inc.ip_address || "0.0.0.0";
        const threat = inc["Threat Type"] || inc.threat_type || "Unknown";
        const risk = inc["Risk Score"] || inc.risk_score || 0;
        const severity = inc["Severity"] || inc.severity || "Low";
        const status = inc["Status"] || inc.status || "Pending Approval";
        const action = inc["Executed Action"] || inc.executed_action || "None";
        
        const row = document.createElement("tr");
        row.onclick = () => viewIncidentDetail(id);

        // Risk coloring
        let riskColor = "var(--text-primary)";
        if (risk >= 80) riskColor = "var(--severity-critical)";
        else if (risk >= 60) riskColor = "var(--severity-high)";
        else if (risk >= 40) riskColor = "var(--severity-medium)";
        
        // Actions cell content
        let actionCellContent = `<span class="text-muted">No Action</span>`;
        if (action === "Block IP" && status === "Action Executed") {
            actionCellContent = `<button class="btn-undo" onclick="triggerRollback('${id}', '${ip}', event)">↩️ Undo Block</button>`;
        } else if (status === "Rolled Back") {
            actionCellContent = `<span class="badge badge-rolledback">Rolled Back</span>`;
        }

        row.innerHTML = `
            <td class="code" title="${id}">${id.substring(0, 8)}...</td>
            <td style="white-space: nowrap;">${formatDateString(ts)}</td>
            <td class="code">${ip}</td>
            <td style="font-weight: 600;">${threat}</td>
            <td class="code" style="color: ${riskColor}; font-weight: 800;">${risk}/100</td>
            <td><span class="badge badge-${severity.toLowerCase()}">${severity}</span></td>
            <td><span class="badge badge-${status.replace(" ", "").toLowerCase()}">${status}</span></td>
            <td style="text-align: right;">${actionCellContent}</td>
        `;
        tbody.appendChild(row);
    });
}

function renderBlockedIps() {
    const listContainer = document.getElementById("blockedIpsList");
    if (blockedIps.length === 0) {
        listContainer.innerHTML = `<div class="empty-state">No IP addresses blocked in firewall.</div>`;
        return;
    }

    listContainer.innerHTML = "";
    blockedIps.forEach(ip => {
        const item = document.createElement("div");
        item.className = "block-item";
        
        // Find if we have an active incident linked to this IP to trigger rollback
        const linkedInc = incidents.find(i => (i["IP Address"] === ip || i.ip_address === ip) && (i["Status"] === "Action Executed" || i.status === "Action Executed"));
        let actionBtn = "";
        if (linkedInc) {
            const incId = linkedInc["Incident ID"] || linkedInc.id;
            actionBtn = `<button class="btn-undo" onclick="triggerRollback('${incId}', '${ip}', event)">Undo</button>`;
        }

        item.innerHTML = `
            <span class="block-ip">${ip}</span>
            ${actionBtn}
        `;
        listContainer.appendChild(item);
    });
}

function calculateStats() {
    document.getElementById("statTotalIncidents").innerText = incidents.length;
    document.getElementById("statBlockedIps").innerText = blockedIps.length;
    
    const escalationsCount = incidents.filter(i => (i["Status"] === "Pending Approval" || i.status === "Pending Approval")).length;
    document.getElementById("statEscalations").innerText = escalationsCount;
}

function renderTimeline(timeline) {
    const container = document.getElementById("mdTimeline");
    container.innerHTML = "";
    
    if (typeof timeline === "string") {
        // Mock timeline contains raw string lines, parse it
        const lines = timeline.split("\n");
        lines.forEach(line => {
            if (!line.trim()) return;
            const match = line.match(/^\[(.*?)\] (.*?): (.*)$/);
            if (match) {
                const item = document.createElement("div");
                item.className = "timeline-visual-item";
                item.innerHTML = `
                    <div class="timeline-dot"></div>
                    <div class="timeline-visual-content">
                        <h5>${match[2]}</h5>
                        <p>${match[3]}</p>
                        <span class="timeline-time">${formatDateString(match[1])}</span>
                    </div>
                `;
                container.appendChild(item);
            } else {
                const item = document.createElement("div");
                item.className = "timeline-visual-item";
                item.innerHTML = `
                    <div class="timeline-dot"></div>
                    <div class="timeline-visual-content">
                        <p>${line}</p>
                    </div>
                `;
                container.appendChild(item);
            }
        });
    } else if (Array.isArray(timeline)) {
        timeline.forEach(event => {
            const item = document.createElement("div");
            item.className = "timeline-visual-item";
            item.innerHTML = `
                <div class="timeline-dot"></div>
                <div class="timeline-visual-content">
                    <h5>${event.event}</h5>
                    <p>${event.description}</p>
                    <span class="timeline-time">${formatDateString(event.timestamp)}</span>
                </div>
            `;
            container.appendChild(item);
        });
    }

    if (container.children.length === 0) {
        container.innerHTML = `<div class="empty-state">No timeline events recorded.</div>`;
    }
}

// --- Modals UI Actions ---

function openModal(modalId) {
    document.getElementById(modalId).classList.add("active");
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.remove("active");
}

function toggleCustomReason() {
    const val = document.getElementById("rollbackReasonSelect").value;
    const group = document.getElementById("customReasonGroup");
    if (val === "custom") {
        group.classList.remove("hidden");
    } else {
        group.classList.add("hidden");
    }
}

// --- Helper Functions ---

async function AppFetch(url, options = {}) {
    try {
        const response = await fetch(url, options);
        if (response.ok) {
            return await response.json();
        } else {
            const errData = await response.json();
            showToast(errData.detail || "API response error.", "error");
            return null;
        }
    } catch (e) {
        showToast("Network response failed.", "error");
        return null;
    }
}

function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span>${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
    `;
    container.appendChild(toast);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function formatDateString(dateStr) {
    if (!dateStr) return "";
    try {
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) return dateStr;
        return date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) {
        return dateStr;
    }
}

function parseJsonSafe(str) {
    if (!str) return null;
    try {
        return JSON.parse(str);
    } catch (e) {
        return null;
    }
}
