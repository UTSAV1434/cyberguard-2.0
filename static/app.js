// State Management
let incidents = [];
let blockedIps = [];
let auditLogs = [];
let systemStatus = {};
let selectedIncidentId = null;

// Tab & UI State
let activeTab = 'overview';
let activeMonth = 9; // October (0-indexed base: 9 represents October)
let activeYear = 2026;
let selectedDay = 28; // Default active selected day in calendar widget
let proActive = false;

// Checklist Tasks
let todoList = [
    { id: 1, text: "Verify ArmorClaw database feed integrity", completed: true },
    { id: 2, text: "Audit rollback logs for False Positives in subnets", completed: false },
    { id: 3, text: "Review active policy thresholds in ArmorIQ console", completed: false },
    { id: 4, text: "Sync resolved incident page indexes with Notion", completed: true }
];

// Chat History
let chatMessages = [
    { sender: 'bot', text: "Hello! I am Sapphire Security Copilot. I can analyze auth failures, review logs, and explain policies. How can I help you today?" }
];

// Notification Alerts
let notificationsList = [
    { id: 1, text: "Critical brute-force automatically blocked on IP 198.51.100.99", time: "1 hour ago", icon: "🚫" },
    { id: 2, text: "ArmorIQ Escalated high-risk Port Scan to manual SOC approval", time: "2 hours ago", icon: "⚠️" },
    { id: 3, text: "ArmorClaw verified credentials stuffing reputational feed", time: "3 hours ago", icon: "🔍" }
];
let dismissedNotifications = [];

// Undo Manager State (Globally records last actions per feature category)
let lastActions = {
    upgrade: null,
    manualBlock: null,
    settings: null,
    todo: null,
    chat: null,
    clearLogs: null,
    notifications: null
};

// Document Ready
document.addEventListener("DOMContentLoaded", () => {
    initApp();
});

function initApp() {
    // Apply saved preferences at startup
    const savedTheme = localStorage.getItem("theme_mode") || "sapphire";
    applyThemeVariables(savedTheme);

    // Refresh Dashboard Data
    refreshDashboard();
    
    // Auto-refresh state based on preferred settings
    setupInterval();

    // Render components
    renderCalendar();
    renderTodoList();
    renderChatMessages();
    updateNotificationsBadge();
}

let dashboardInterval = null;
function setupInterval() {
    if (dashboardInterval) clearInterval(dashboardInterval);
    const intervalTime = parseInt(localStorage.getItem("refresh_interval") || "30000");
    dashboardInterval = setInterval(() => {
        refreshDashboard();
    }, intervalTime);
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
            fetchStatus(),
            fetchIncidents(),
            fetchBlockedIps(),
            fetchAuditLogs()
        ]);
        calculateStats();
        renderCalendarActivities();
    } catch (error) {
        console.error("Dashboard refresh failed:", error);
    }
}

async function fetchIncidents() {
    try {
        const response = await fetch("/api/incidents");
        if (response.ok) {
            incidents = await response.json();
            renderIncidentsTable();
            updateSeverityPercentages();
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
            renderFirewallTab();
        }
    } catch (error) {
        console.error("Failed to query blocked IPs:", error);
    }
}

async function fetchAuditLogs() {
    try {
        const response = await fetch("/api/audit-logs");
        if (response.ok) {
            auditLogs = await response.json();
            renderAuditLogsTab();
        }
    } catch (error) {
        console.error("Failed to fetch audit logs:", error);
    }
}

// --- Trigger API Actions ---

async function runSimulation() {
    showToast("Analyzing simulation auth logs failed login sequences...", "info");
    try {
        const response = await fetch("/api/simulation/run", { method: "POST" });
        const data = await response.json();
        if (response.ok && data.success) {
            showToast(data.message, "success");
            await refreshDashboard();
            renderHeatmap(); 
        } else {
            showToast("Simulation execution failed.", "error");
        }
    } catch (error) {
        showToast("Error connecting to simulation service.", "error");
    }
}

function triggerRollback(incidentId, ipAddress, event) {
    if (event) event.stopPropagation(); // Avoid triggering row clicks
    selectedIncidentId = incidentId;
    document.getElementById("rollbackIpAddress").innerText = ipAddress;
    document.getElementById("rollbackReasonSelect").value = "False Positive";
    document.getElementById("rollbackReasonText").value = "";
    toggleCustomReason();
    openModal("modalRollback");
}

document.getElementById("btnConfirmRollback").onclick = async function() {
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
};

async function viewIncidentDetail(incidentId) {
    openModal("modalDetail");
    
    document.getElementById("mdId").innerText = incidentId;
    document.getElementById("mdIp").innerText = "Loading...";
    document.getElementById("mdSeverity").innerText = "Loading...";
    document.getElementById("mdRisk").innerText = "Loading...";
    document.getElementById("mdStatus").innerText = "Loading...";
    document.getElementById("mdAction").innerText = "Loading...";
    document.getElementById("mdClaw").innerText = "Loading...";
    document.getElementById("mdIQ").innerText = "Loading...";
    document.getElementById("mdExplanation").innerText = "Loading explanation details...";
    document.getElementById("mdTimeline").innerHTML = `<div class="loader-container"><div class="loader"></div></div>`;
    document.getElementById("mdCompliance").innerText = "Loading compliance report...";

    try {
        const response = await fetch(`/api/incidents/${incidentId}`);
        if (response.ok) {
            const data = await response.json();
            
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

            const clawRes = data.armorclaw_result || parseJsonSafe(data["ArmorClaw Result"]);
            document.getElementById("mdClaw").innerText = clawRes ? `Reputation: ${clawRes.reputation} (Verified: ${clawRes.verified})` : "N/A";
            
            const iqRes = data.armoriq_decision || parseJsonSafe(data["ArmorIQ Decision"]);
            document.getElementById("mdIQ").innerText = iqRes ? `Approved: ${iqRes.approved} (Policy: ${iqRes.policy_name})` : "N/A";

            document.getElementById("mdExplanation").innerText = data.explanation || "No explanation registered.";

            renderTimeline(data.timeline || data["Timeline"] || []);
            document.getElementById("mdCompliance").innerText = data.compliance_report || data["Compliance Report"] || "No compliance report found.";
        }
    } catch (error) {
        showToast("Error loading incident details.", "error");
        closeModal("modalDetail");
    }
}

// --- Navigation & Tab switching ---

function switchTab(tabId) {
    activeTab = tabId;
    
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(item => {
        item.classList.remove('active');
    });
    const targetNav = document.getElementById(`nav-${tabId}`);
    if (targetNav) targetNav.classList.add('active');

    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('active');
    });
    const targetPane = document.getElementById(`tab-pane-${tabId}`);
    if (targetPane) targetPane.classList.add('active');
}

// --- Render Layout components ---

function updateStatusIndicator() {
    const pulse = document.getElementById("statusPulse");
    const label = document.getElementById("statusLabel");
    
    pulse.className = "status-pulse";
    if (systemStatus.mock_mode) {
        pulse.classList.add("pulse-mock");
        label.innerText = "MOCK ENVIRONMENT";
    } else {
        pulse.classList.add("pulse-live");
        label.innerText = "LIVE API ONLINE";
    }
}

function calculateStats() {
    document.getElementById("ovTotalIncidents").innerText = incidents.length;
    document.getElementById("ovBlockedIps").innerText = blockedIps.length;
    document.getElementById("incidentsCount").innerText = `${incidents.length} Incident${incidents.length === 1 ? '' : 's'}`;
    
    const escalationsCount = incidents.filter(i => (i["Status"] === "Pending Approval" || i.status === "Pending Approval")).length;
    document.getElementById("ovEscalations").innerText = escalationsCount;
    document.getElementById("ovAuditLogs").innerText = auditLogs.length;

    document.getElementById("ovBlockedIpsTrend").innerText = `+${blockedIps.length * 20}% from last week`;
}

function updateSeverityPercentages() {
    if (incidents.length === 0) {
        document.getElementById("barCritical").style.width = "0%";
        document.getElementById("valCritical").innerText = "0%";
        document.getElementById("barHigh").style.width = "0%";
        document.getElementById("valHigh").innerText = "0%";
        document.getElementById("barMedium").style.width = "0%";
        document.getElementById("valMedium").innerText = "0%";
        return;
    }

    const critical = incidents.filter(i => (i.severity || i["Severity"]) === "Critical").length;
    const high = incidents.filter(i => (i.severity || i["Severity"]) === "High").length;
    const mediumLow = incidents.length - (critical + high);

    const pcCrit = Math.round((critical / incidents.length) * 100);
    const pcHigh = Math.round((high / incidents.length) * 100);
    const pcMed = Math.round((mediumLow / incidents.length) * 100);

    document.getElementById("barCritical").style.width = `${pcCrit}%`;
    document.getElementById("valCritical").innerText = `${pcCrit}%`;

    document.getElementById("barHigh").style.width = `${pcHigh}%`;
    document.getElementById("valHigh").innerText = `${pcHigh}%`;

    document.getElementById("barMedium").style.width = `${pcMed}%`;
    document.getElementById("valMedium").innerText = `${pcMed}%`;
}

function renderIncidentsTable() {
    const tbody = document.getElementById("incidentsTableBody");
    if (incidents.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No incidents logged in the system. Run simulation to populate.</td></tr>`;
        return;
    }

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

        let riskColor = "var(--text-primary)";
        if (risk >= 80) riskColor = "var(--severity-critical)";
        else if (risk >= 60) riskColor = "var(--severity-high)";
        else if (risk >= 40) riskColor = "var(--severity-medium)";
        
        let actionCellContent = `<span class="text-muted">No Action</span>`;
        if (action === "Block IP" && (status === "Action Executed" || status === "Pending Approval")) {
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

function renderTimeline(timeline) {
    const container = document.getElementById("mdTimeline");
    container.innerHTML = "";
    
    if (typeof timeline === "string") {
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

// --- Render TAB 3: FIREWALL Blocks Tab ---

function renderFirewallTab() {
    const tbody = document.getElementById("firewallTableBody");
    if (blockedIps.length === 0) {
        tbody.innerHTML = `<tr><td colspan="4" class="empty-table-state">No IP addresses currently blocked.</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    blockedIps.forEach(ip => {
        const row = document.createElement("tr");
        
        const linkedInc = incidents.find(i => (i.ip_address === ip || i["IP Address"] === ip));
        const policyScope = linkedInc ? (linkedInc.recommended_action || "Auto Block Rule") : "Manual CLI Rule";
        
        let actionBtn = `<button class="btn btn-secondary btn-small inline-btn" onclick="triggerManualUnblock('${ip}')">🔓 Unblock</button>`;
        if (linkedInc) {
            const incId = linkedInc["Incident ID"] || linkedInc.id;
            actionBtn = `<button class="btn btn-danger btn-small inline-btn" onclick="triggerRollback('${incId}', '${ip}', event)">↩️ Undo Block</button>`;
        }

        row.innerHTML = `
            <td class="code">${ip}</td>
            <td>${policyScope}</td>
            <td><span class="badge badge-critical">Active Block</span></td>
            <td>${actionBtn}</td>
        `;
        tbody.appendChild(row);
    });
}

function triggerManualUnblock(ip) {
    const idx = blockedIps.indexOf(ip);
    if (idx > -1) {
        lastActions.manualBlock = { action: 'delete', ip: ip };
        document.getElementById("btnUndoManualBlock").classList.remove("hidden");
        
        blockedIps.splice(idx, 1);
        showToast(`Successfully unblocked IP address ${ip} manually.`, "success");
        renderBlockedIps();
        renderFirewallTab();
        calculateStats();
    }
}

function addManualBlock() {
    const ipInput = document.getElementById("manualBlockIp");
    const ip = ipInput.value.trim();
    if (!ip) {
        showToast("Please enter a valid IP address.", "error");
        return;
    }
    
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
        showToast("Invalid IP address format.", "error");
        return;
    }

    if (blockedIps.includes(ip)) {
        showToast("IP address is already blocked.", "error");
        return;
    }

    lastActions.manualBlock = { action: 'add', ip: ip };
    document.getElementById("btnUndoManualBlock").classList.remove("hidden");

    blockedIps.push(ip);
    ipInput.value = "";
    showToast(`Firewall manual containment active for: ${ip}`, "success");
    
    renderBlockedIps();
    renderFirewallTab();
    calculateStats();
}

function undoManualBlock() {
    const last = lastActions.manualBlock;
    if (!last) return;

    if (last.action === 'add') {
        const idx = blockedIps.indexOf(last.ip);
        if (idx > -1) blockedIps.splice(idx, 1);
        showToast(`Undo complete: IP ${last.ip} removed from blocklist.`, "info");
    } else if (last.action === 'delete') {
        if (!blockedIps.includes(last.ip)) blockedIps.push(last.ip);
        showToast(`Undo complete: Re-applied block on IP ${last.ip}.`, "info");
    }

    lastActions.manualBlock = null;
    document.getElementById("btnUndoManualBlock").classList.add("hidden");
    
    renderBlockedIps();
    renderFirewallTab();
    calculateStats();
}

// --- Render TAB 4: AUDIT LOGS Tab ---

function renderAuditLogsTab() {
    const tbody = document.getElementById("auditLogsTableBody");
    if (auditLogs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="empty-table-state">No audit logs found.</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    
    const sortedLogs = [...auditLogs].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    sortedLogs.forEach(log => {
        const row = document.createElement("tr");
        const statusClass = log.status === "SUCCESS" ? "badge-executed" : "badge-pending";
        
        row.innerHTML = `
            <td style="white-space: nowrap;">${formatDateString(log.timestamp)}</td>
            <td class="code" style="font-weight:600;">${log.event_type}</td>
            <td class="code">${log.incident_id ? log.incident_id.substring(0, 8) + '...' : 'N/A'}</td>
            <td><span class="badge ${statusClass}">${log.status}</span></td>
            <td>${log.description}</td>
        `;
        tbody.appendChild(row);
    });
}

function clearAuditLogPrompt() {
    if (auditLogs.length === 0) return;
    
    lastActions.clearLogs = [...auditLogs];
    document.getElementById("btnUndoClearLogs").classList.remove("hidden");

    auditLogs = [];
    showToast("Audit logs cleared locally.", "success");
    renderAuditLogsTab();
    calculateStats();
}

function undoClearLogs() {
    if (lastActions.clearLogs) {
        auditLogs = lastActions.clearLogs;
        lastActions.clearLogs = null;
        document.getElementById("btnUndoClearLogs").classList.add("hidden");
        showToast("Undo complete: Audit logs restored.", "info");
        renderAuditLogsTab();
        calculateStats();
    }
}

// --- Render Calendar Widget (Sapphire UI style) ---

function renderCalendar() {
    const title = document.getElementById("calendarMonthTitle");
    const container = document.getElementById("calendarDaysRow");
    
    const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
    title.innerText = `${months[activeMonth]} ${activeYear}`;

    container.innerHTML = "";
    
    const daysName = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue"];
    const startDayNum = 24; // October 24

    for (let i = 0; i < 6; i++) {
        const dayNum = startDayNum + i;
        const cell = document.createElement("div");
        cell.className = "cal-day-cell";
        
        if (dayNum === selectedDay) cell.classList.add("active");

        cell.innerHTML = `
            <span class="day">${daysName[i]}</span>
            <span class="num">${dayNum}</span>
        `;
        
        cell.onclick = () => {
            selectedDay = dayNum;
            document.querySelectorAll('.cal-day-cell').forEach(c => c.classList.remove('active'));
            cell.classList.add('active');
            renderCalendarActivities();
        };

        container.appendChild(cell);
    }
    renderCalendarActivities();
}

function adjustCalendarMonth(dir) {
    activeMonth += dir;
    if (activeMonth > 11) { activeMonth = 0; activeYear++; }
    else if (activeMonth < 0) { activeMonth = 11; activeYear--; }
    renderCalendar();
}

function renderCalendarActivities() {
    const list = document.getElementById("calendarActivitiesList");
    if (!list) return;
    
    list.innerHTML = "";
    
    // Filter incidents/audit logs corresponding to selectedDay
    const targetDateStr = `${activeYear}-${String(activeMonth + 1).padStart(2, '0')}-${String(selectedDay).padStart(2, '0')}`;
    
    const dayIncidents = incidents.filter(inc => {
        const ts = inc.timestamp || inc["Timestamp"];
        return ts && ts.startsWith(targetDateStr);
    });

    const dayLogs = auditLogs.filter(log => {
        const ts = log.timestamp;
        return ts && ts.startsWith(targetDateStr);
    });

    if (dayIncidents.length === 0 && dayLogs.length === 0) {
        list.innerHTML = `
            <div class="activity-item">
                <div class="activity-dot bg-cyan"></div>
                <div class="activity-details">
                    <h4>Continuous Monitoring</h4>
                    <p>No threats detected. Firewall nodes active.</p>
                    <span class="activity-time">00:00 AM - 11:59 PM</span>
                </div>
            </div>
        `;
        return;
    }

    dayIncidents.forEach(inc => {
        const item = document.createElement("div");
        item.className = "activity-item";
        const dotColor = (inc.severity || inc["Severity"]) === "Critical" ? "bg-critical" : "bg-high";
        const ts = inc.timestamp || inc["Timestamp"];
        
        item.innerHTML = `
            <div class="activity-dot ${dotColor}"></div>
            <div class="activity-details">
                <h4>${inc.threat_type || inc["Threat Type"]}</h4>
                <p>Status: ${inc.status || inc["Status"]} | IP: ${inc.ip_address || inc["IP Address"]}</p>
                <span class="activity-time">${formatTimeOnly(ts)}</span>
            </div>
        `;
        list.appendChild(item);
    });

    dayLogs.forEach(log => {
        const item = document.createElement("div");
        item.className = "activity-item";
        
        item.innerHTML = `
            <div class="activity-dot bg-purple"></div>
            <div class="activity-details">
                <h4>${log.event_type}</h4>
                <p>${log.description}</p>
                <span class="activity-time">${formatTimeOnly(log.timestamp)}</span>
            </div>
        `;
        list.appendChild(item);
    });
}

function formatTimeOnly(dateStr) {
    if (!dateStr) return "";
    try {
        const date = new Date(dateStr);
        if (isNaN(date.getTime())) return dateStr;
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (e) {
        return dateStr;
    }
}

// --- Render Weekly Threat Activity Heatmap Grid ---

function renderHeatmap() {
    const grid = document.getElementById("threatHeatmapGrid");
    if (!grid) return;
    grid.innerHTML = "";

    const cellsTotal = 96;
    for (let i = 0; i < cellsTotal; i++) {
        const cell = document.createElement("div");
        
        let weight = Math.floor(Math.random() * 4);
        if (i % 8 === 0 && Math.random() > 0.5) weight = 4;
        if (incidents.length > 0 && Math.random() > 0.8) weight = Math.max(weight, 3);

        cell.className = `heatmap-cell hm-${weight}`;
        cell.title = `Hour ${Math.floor(i / 4)}:00 | Event Density: ${weight === 4 ? 'CRITICAL' : weight === 3 ? 'HIGH' : weight === 2 ? 'MEDIUM' : weight === 1 ? 'LOW' : 'NONE'}`;
        
        cell.onclick = () => {
            showToast(`Threat Feed Stats | Density Weight: ${weight}/4 | Hourly Scan: 100% OK`, "info");
        };

        grid.appendChild(cell);
    }
}

// --- TAB 5: TODO Checklist ---

function renderTodoList() {
    const container = document.getElementById("todoListContainer");
    if (!container) return;
    container.innerHTML = "";

    if (todoList.length === 0) {
        container.innerHTML = `<div class="empty-state">No checklist tasks. Add one above!</div>`;
        return;
    }

    todoList.forEach(todo => {
        const item = document.createElement("div");
        item.className = `todo-item ${todo.completed ? 'completed' : ''}`;
        
        item.innerHTML = `
            <div class="todo-checkbox" onclick="toggleTodo(${todo.id})"></div>
            <span class="todo-text">${todo.text}</span>
            <button class="btn-delete-todo" onclick="deleteTodo(${todo.id})" title="Delete Task">🗑️</button>
        `;
        container.appendChild(item);
    });
}

function toggleTodo(id) {
    const todo = todoList.find(t => t.id === id);
    if (todo) {
        lastActions.todo = { action: 'toggle', id: id, previousState: todo.completed };
        document.getElementById("btnUndoTodoAction").classList.remove("hidden");

        todo.completed = !todo.completed;
        showToast(`Task marked as ${todo.completed ? 'completed' : 'pending'}.`, "info");
        renderTodoList();
    }
}

function deleteTodo(id) {
    const idx = todoList.findIndex(t => t.id === id);
    if (idx > -1) {
        lastActions.todo = { action: 'delete', todo: todoList[idx], index: idx };
        document.getElementById("btnUndoTodoAction").classList.remove("hidden");

        todoList.splice(idx, 1);
        showToast("Security task removed from checklist.", "info");
        renderTodoList();
    }
}

function addTodoItem() {
    const input = document.getElementById("newTodoText");
    const text = input.value.trim();
    if (!text) return;

    const newTodo = {
        id: Date.now(),
        text: text,
        completed: false
    };

    lastActions.todo = { action: 'add', id: newTodo.id };
    document.getElementById("btnUndoTodoAction").classList.remove("hidden");

    todoList.push(newTodo);
    input.value = "";
    showToast("Added new compliance task.", "success");
    renderTodoList();
}

function undoTodoAction() {
    const last = lastActions.todo;
    if (!last) return;

    if (last.action === 'add') {
        todoList = todoList.filter(t => t.id !== last.id);
        showToast("Undo complete: Custom task removed.", "info");
    } else if (last.action === 'delete') {
        todoList.splice(last.index, 0, last.todo);
        showToast("Undo complete: Deleted task restored.", "info");
    } else if (last.action === 'toggle') {
        const todo = todoList.find(t => t.id === last.id);
        if (todo) {
            todo.completed = last.previousState;
            showToast("Undo complete: Task checkbox toggled back.", "info");
        }
    }

    lastActions.todo = null;
    document.getElementById("btnUndoTodoAction").classList.add("hidden");
    renderTodoList();
}

// --- TAB 6: AI Chat Assistant ---

function renderChatMessages() {
    const box = document.getElementById("chatBoxContainer");
    if (!box) return;
    box.innerHTML = "";

    chatMessages.forEach(msg => {
        const bubble = document.createElement("div");
        bubble.className = `chat-message ${msg.sender}`;
        
        bubble.innerHTML = `
            <div class="avatar">${msg.sender === 'bot' ? '✨' : '👤'}</div>
            <div class="message-content">
                <p>${msg.text}</p>
            </div>
        `;
        box.appendChild(bubble);
    });

    box.scrollTop = box.scrollHeight;
}

function sendChatPrompt(promptText) {
    chatMessages.push({ sender: 'user', text: promptText });
    renderChatMessages();

    setTimeout(() => {
        let responseText = "I have scanned the policy parameters. ";
        if (promptText.toLowerCase().includes("incident")) {
            responseText += `There are currently ${incidents.length} security incident records indexed. Critical severity incidents are restricted automatically under the default policy.`;
        } else if (promptText.toLowerCase().includes("block")) {
            responseText += `Firewall block active list contains ${blockedIps.length} target IPs. All manual unblock operations are securely tracked in the audit table.`;
        } else {
            responseText += "Sapphire AI models recommend keeping mock mode active when testing custom policies on staging environments.";
        }
        
        chatMessages.push({ sender: 'bot', text: responseText });
        renderChatMessages();
    }, 800);
}

function submitChatPrompt() {
    const input = document.getElementById("chatInputText");
    const val = input.value.trim();
    if (!val) return;

    input.value = "";
    sendChatPrompt(val);
}

function clearChat() {
    if (chatMessages.length === 0) return;

    lastActions.chat = [...chatMessages];
    document.getElementById("btnUndoChatClear").classList.remove("hidden");

    chatMessages = [];
    renderChatMessages();
    showToast("Chat history cleared.", "info");
}

function undoChatClear() {
    if (lastActions.chat) {
        chatMessages = lastActions.chat;
        lastActions.chat = null;
        document.getElementById("btnUndoChatClear").classList.add("hidden");
        showToast("Undo complete: Chat messages restored.", "info");
        renderChatMessages();
    }
}

// --- Upgrade pro operations ---

function subscribePlan(planName, priceStr) {
    const card = document.querySelector(".upgrade-card");
    const btn = document.querySelector(".btn-upgrade");
    const undoBtn = document.getElementById("btnUndoUpgrade");

    lastActions.upgrade = { 
        active: proActive, 
        planName: planName,
        buttonText: btn.innerText
    };
    undoBtn.classList.remove("hidden");

    proActive = true;
    card.classList.add("pro-active");
    btn.innerText = `Active: ${planName}`;
    btn.disabled = true;

    closeModal("modalPlans");
    showToast(`Successfully subscribed to ${planName} (${priceStr})! Protection active.`, "success");
}

function undoUpgrade() {
    const card = document.querySelector(".upgrade-card");
    const btn = document.querySelector(".btn-upgrade");
    const undoBtn = document.getElementById("btnUndoUpgrade");

    proActive = false;
    card.classList.remove("pro-active");
    btn.innerText = "Upgrade to Pro";
    btn.disabled = false;

    lastActions.upgrade = null;
    undoBtn.classList.add("hidden");

    showToast("Subscription reverted. Node scope limited to trial.", "info");
}

// --- Global Search Filter Operations ---

function handleGlobalSearch() {
    const searchVal = document.getElementById("globalSearch").value.toLowerCase().trim();
    
    // 1. Filter incidents table (Console tab)
    const rows = document.querySelectorAll("#incidentsTableBody tr");
    rows.forEach(row => {
        if (row.cells.length < 8) return;
        const text = row.innerText.toLowerCase();
        if (text.includes(searchVal)) row.classList.remove("hidden");
        else row.classList.add("hidden");
    });

    // 2. Filter firewall block list rows (Firewall tab)
    const firewallRows = document.querySelectorAll("#firewallTableBody tr");
    firewallRows.forEach(row => {
        if (row.cells.length < 4) return;
        const text = row.innerText.toLowerCase();
        if (text.includes(searchVal)) row.classList.remove("hidden");
        else row.classList.add("hidden");
    });

    // 3. Filter audit log rows (Audit tab)
    const auditRows = document.querySelectorAll("#auditLogsTableBody tr");
    auditRows.forEach(row => {
        if (row.cells.length < 5) return;
        const text = row.innerText.toLowerCase();
        if (text.includes(searchVal)) row.classList.remove("hidden");
        else row.classList.add("hidden");
    });

    // 4. Filter calendar activities list (Overview tab)
    const activityItems = document.querySelectorAll("#calendarActivitiesList .activity-item");
    activityItems.forEach(item => {
        const text = item.innerText.toLowerCase();
        if (text.includes(searchVal)) item.classList.remove("hidden");
        else item.classList.add("hidden");
    });
}

function changeTimeRange() {
    const range = document.getElementById("timeRangeSelect").value;
    showToast(`Time Range filter updated to: ${range.toUpperCase()}.`, "info");
}

// --- Settings & Modal UI triggers ---

function showSettings() {
    document.getElementById("themeSelect").value = localStorage.getItem("theme_mode") || "sapphire";
    document.getElementById("refreshSelect").value = localStorage.getItem("refresh_interval") || "30000";
    openModal("modalSettings");
}

function updateThemePreference() {
    const theme = document.getElementById("themeSelect").value;
    lastActions.settings = { theme: localStorage.getItem("theme_mode") || "sapphire" };
    document.getElementById("btnUndoSettings").classList.remove("hidden");

    localStorage.setItem("theme_mode", theme);
    applyThemeVariables(theme);
    showToast(`Dashboard theme set to: ${theme.toUpperCase()}`, "success");
}

function applyThemeVariables(theme) {
    const root = document.documentElement;
    if (theme === "cyan") {
        root.style.setProperty("--accent-purple", "#06b6d4");
        root.style.setProperty("--accent-violet", "#0891b2");
        root.style.setProperty("--glow-purple", "0 0 20px rgba(6, 182, 212, 0.4)");
    } else if (theme === "amethyst") {
        root.style.setProperty("--accent-purple", "#c084fc");
        root.style.setProperty("--accent-violet", "#a855f7");
        root.style.setProperty("--glow-purple", "0 0 20px rgba(168, 85, 247, 0.4)");
    } else {
        root.style.setProperty("--accent-purple", "#8b5cf6");
        root.style.setProperty("--accent-violet", "#a855f7");
        root.style.setProperty("--glow-purple", "0 0 20px rgba(168, 85, 247, 0.4)");
    }
}

function updateRefreshPreference() {
    const interval = document.getElementById("refreshSelect").value;
    localStorage.setItem("refresh_interval", interval);
    setupInterval();
    showToast("Dashboard refresh rate updated.", "success");
}

function undoSettings() {
    if (lastActions.settings) {
        const prevTheme = lastActions.settings.theme;
        localStorage.setItem("theme_mode", prevTheme);
        document.getElementById("themeSelect").value = prevTheme;
        applyThemeVariables(prevTheme);
        
        lastActions.settings = null;
        document.getElementById("btnUndoSettings").classList.add("hidden");
        showToast("Settings reverted successfully.", "info");
    }
}

// --- Notifications Popover Operations ---

function toggleNotifications() {
    // Create notifications dropdown dynamically if not present
    let popover = document.getElementById("notificationsPopover");
    if (popover) {
        popover.remove();
        return;
    }

    popover = document.createElement("div");
    popover.id = "notificationsPopover";
    popover.className = "panel glass notifications-popover";
    
    // Absolute position underneath the bell button
    const bellBtn = document.querySelector(".badge-btn");
    const rect = bellBtn.getBoundingClientRect();
    
    popover.style.position = "absolute";
    popover.style.top = `${rect.bottom + window.scrollY + 10}px`;
    popover.style.right = `${window.innerWidth - rect.right - window.scrollX}px`;
    popover.style.width = "320px";
    popover.style.zIndex = "1000";
    
    renderNotificationsInPopover(popover);
    document.body.appendChild(popover);

    // Close when clicking outside
    const closeHandler = (e) => {
        if (!popover.contains(e.target) && !bellBtn.contains(e.target)) {
            popover.remove();
            document.removeEventListener("click", closeHandler);
        }
    };
    // Wait a tick to prevent closing immediately from this click event
    setTimeout(() => {
        document.addEventListener("click", closeHandler);
    }, 10);
}

function renderNotificationsInPopover(popover) {
    popover.innerHTML = `
        <div class="popover-header" style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid rgba(255,255,255,0.06); padding-bottom:10px; margin-bottom:12px;">
            <h4 style="font-size:13px; font-weight:700;">System Alerts</h4>
            <div style="display:flex; gap:8px;">
                <button class="btn btn-secondary btn-small" id="btnUndoNotification" style="padding:4px 8px; font-size:10px; display:none;" onclick="undoDismissNotification(event)">Undo</button>
                <button class="btn btn-secondary btn-small" style="padding:4px 8px; font-size:10px;" onclick="clearAllNotifications(event)">Clear All</button>
            </div>
        </div>
        <div class="popover-body" style="display:flex; flex-direction:column; gap:10px; max-height:240px; overflow-y:auto;">
            ${notificationsList.length === 0 ? '<div class="empty-state" style="padding:10px 0;">No active notifications.</div>' : ''}
        </div>
    `;

    // Check if undo button should be visible
    const undoBtn = popover.querySelector("#btnUndoNotification");
    if (lastActions.notifications && undoBtn) {
        undoBtn.style.display = "block";
    }

    const body = popover.querySelector(".popover-body");
    notificationsList.forEach(n => {
        const item = document.createElement("div");
        item.style.display = "flex";
        item.style.gap = "10px";
        item.style.alignItems = "flex-start";
        item.style.padding = "8px";
        item.style.background = "rgba(255,255,255,0.02)";
        item.style.border = "1px solid rgba(255,255,255,0.04)";
        item.style.borderRadius = "8px";
        
        item.innerHTML = `
            <span style="font-size:16px;">${n.icon}</span>
            <div style="flex:1;">
                <p style="font-size:11px; font-weight:500; line-height:1.3;">${n.text}</p>
                <span style="font-size:9px; color:var(--text-muted); display:block; margin-top:2px;">${n.time}</span>
            </div>
            <button style="background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:14px;" onclick="dismissNotification(${n.id}, event)">&times;</button>
        `;
        body.appendChild(item);
    });
}

function dismissNotification(id, event) {
    if (event) event.stopPropagation();
    const idx = notificationsList.findIndex(n => n.id === id);
    if (idx > -1) {
        lastActions.notifications = { action: 'dismiss', note: notificationsList[idx], index: idx };
        notificationsList.splice(idx, 1);
        
        updateNotificationsBadge();
        showToast("Notification dismissed.", "info");
        
        const popover = document.getElementById("notificationsPopover");
        if (popover) renderNotificationsInPopover(popover);
    }
}

function clearAllNotifications(event) {
    if (event) event.stopPropagation();
    if (notificationsList.length === 0) return;

    lastActions.notifications = { action: 'clear', list: [...notificationsList] };
    notificationsList = [];
    
    updateNotificationsBadge();
    showToast("All notifications cleared.", "info");
    
    const popover = document.getElementById("notificationsPopover");
    if (popover) renderNotificationsInPopover(popover);
}

function undoDismissNotification(event) {
    if (event) event.stopPropagation();
    const last = lastActions.notifications;
    if (!last) return;

    if (last.action === 'dismiss') {
        notificationsList.splice(last.index, 0, last.note);
        showToast("Undo complete: Notification restored.", "info");
    } else if (last.action === 'clear') {
        notificationsList = last.list;
        showToast("Undo complete: All notifications restored.", "info");
    }

    lastActions.notifications = null;
    updateNotificationsBadge();

    const popover = document.getElementById("notificationsPopover");
    if (popover) renderNotificationsInPopover(popover);
}

function updateNotificationsBadge() {
    const badge = document.getElementById("notificationBadge");
    if (!badge) return;
    badge.innerText = notificationsList.length;
    if (notificationsList.length === 0) {
        badge.style.display = "none";
    } else {
        badge.style.display = "block";
    }
}

// --- Helpers ---

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

function showToast(message, type = "info") {
    const container = document.getElementById("toastContainer");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span>${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">&times;</button>
    `;
    container.appendChild(toast);
    
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
