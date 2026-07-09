/* ============================================================
   CONFIGURATION
   ============================================================ */
function resolveApiBase() {
  if (window.API_BASE) return window.API_BASE;
  const savedBase = localStorage.getItem("api_base");
  if (savedBase) return savedBase;

  const { protocol, hostname, port, origin } = window.location;
  if (protocol === "file:" || port === "5500" || port === "3000" || port === "8080") {
    return `http://${hostname || "127.0.0.1"}:8000`;
  }
  return origin;
}

const API_BASE = resolveApiBase();
let API_KEY = localStorage.getItem("api_key") || "";

async function readJson(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`API returned an invalid response from ${response.url}. Check that the backend is running on ${API_BASE}.`);
  }
}

/* ============================================================
   DOM REFERENCES
   ============================================================ */
const sections = {
  dashboard: document.getElementById("section-dashboard"),
  analysis: document.getElementById("section-analysis"),
  history: document.getElementById("section-history"),
  "api-key": document.getElementById("section-api-key"),
};

const navItems = document.querySelectorAll(".nav-item");

/* ============================================================
   NAVIGATION
   ============================================================ */
navItems.forEach((item) => {
  item.addEventListener("click", function(e) {
    e.preventDefault();
    const section = this.dataset.section;
    navigateTo(section);
  });
});

function navigateTo(section) {
  // Update nav items
  navItems.forEach((item) => {
    item.classList.toggle("active", item.dataset.section === section);
  });

  // Update sections
  Object.keys(sections).forEach((key) => {
    sections[key].classList.toggle("active", key === section);
  });

  // Update page title
  const titles = {
    dashboard: "Dashboard",
    analysis: "URL Analysis",
    history: "Request History",
    "api-key": "API Key Management",
  };
  document.getElementById("pageTitle").textContent = titles[section] || "Dashboard";

  // Load data based on section
  if (section === "dashboard") {
    loadDashboard();
  } else if (section === "history") {
    loadHistory();
  } else if (section === "api-key") {
    loadApiKeyInfo();
  }
}

/* ============================================================
   CHECK AUTHENTICATION
   ============================================================ */
function checkAuth() {
  if (!API_KEY) {
    window.location.href = "index.html";
    return false;
  }
  return true;
}

/* ============================================================
   LOGOUT
   ============================================================ */
function handleLogout() {
  if (confirm("Are you sure you want to logout?")) {
    localStorage.removeItem("api_key");
    localStorage.removeItem("access_token");
    localStorage.removeItem("remember_me");
    localStorage.removeItem("user_email");
    window.location.href = "index.html";
  }
}

/* ============================================================
   USER INFO
   ============================================================ */
function updateUserInfo(data) {
  document.getElementById("userNameDisplay").textContent = data.email || "User";
  document.getElementById("userEmailDisplay").textContent = data.email || "-";
  document.getElementById("apiKeyPrefix").textContent = (data.api_key_prefix || "****") + "****";
}

/* ============================================================
   LOAD DASHBOARD
   ============================================================ */
async function loadDashboard() {
  if (!checkAuth()) return;

  try {
    const response = await fetch(`${API_BASE}/dashboard`, {
      headers: { "X-API-Key": API_KEY }
    });

    if (response.status === 401 || response.status === 403) {
      handleLogout();
      return;
    }

    if (!response.ok) {
      console.error("Dashboard fetch failed:", response.status);
      return;
    }

    const data = await readJson(response);

    // Update stats
    document.getElementById("totalRequests").textContent = data.total_requests ?? data.usage_count ?? 0;
    document.getElementById("safeCount").textContent = data.safe_urls ?? 0;
    document.getElementById("suspiciousCount").textContent = data.suspicious_urls ?? 0;
    document.getElementById("maliciousCount").textContent = data.malicious_urls ?? 0;
    document.getElementById("profileEmail").textContent = data.email || "-";
    document.getElementById("profileApiKey").textContent = (data.api_key_prefix || "") + "********";
    document.getElementById("profileUsage").textContent = data.total_requests ?? data.usage_count ?? 0;
    document.getElementById("profileLastLogin").textContent = data.last_login ? new Date(data.last_login).toLocaleString() : "-";
    document.getElementById("profileCreated").textContent = data.created_at ? new Date(data.created_at).toLocaleString() : "-";
    document.getElementById("profileEmailVerified").textContent = data.email_verified ? "Verified" : "Not verified";

    updateUserInfo(data);

    renderRecentActivity(data.recent_activity || []);

  } catch (error) {
    console.error("Dashboard error:", error);
  }
}

async function loadBackendVersion() {
  const versionEl = document.getElementById("backendVersion");
  if (!versionEl) return;

  try {
    const response = await fetch(`${API_BASE}/health`);
    if (!response.ok) throw new Error("Health endpoint unavailable");
    const data = await readJson(response);
    versionEl.textContent = data.version ? `v${data.version}` : "Version unavailable";
  } catch (error) {
    versionEl.textContent = "Version unavailable";
  }
}

/* ============================================================
   LOAD RECENT ACTIVITY
   ============================================================ */
async function loadRecentActivity() {
  try {
    const response = await fetch(`${API_BASE}/recent-requests`, {
      headers: { "X-API-Key": API_KEY }
    });

    if (!response.ok) return;

    const data = await readJson(response);
    renderRecentActivity(data || []);

  } catch (error) {
    console.error("Recent activity error:", error);
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatPercent(value) {
  const numeric = Number(value || 0);
  return `${(numeric * 100).toFixed(1)}%`;
}

function renderRecentActivity(data) {
  const container = document.getElementById("recentActivity");

  if (!data || data.length === 0) {
    container.innerHTML = '<p class="text-muted">No recent activity yet.</p>';
    return;
  }

  const recent = data.slice(0, 5);
  let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
  recent.forEach((item) => {
    const color = item.prediction === "safe" ? "var(--safe)" :
                  item.prediction === "suspicious" ? "var(--suspicious)" : "var(--malicious)";
    html += `
      <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#0d1420;border-radius:6px;flex-wrap:wrap;gap:8px;">
        <span style="font-size:13px;color:var(--text-primary);word-break:break-all;flex:1;">${escapeHtml(item.url)}</span>
        <span style="font-size:12px;font-weight:600;color:${color};">${escapeHtml(item.prediction).toUpperCase()}</span>
        <span style="font-size:11px;color:var(--text-muted);">${new Date(item.created_at).toLocaleString()}</span>
      </div>
    `;
  });
  html += '</div>';
  container.innerHTML = html;
}

/* ============================================================
   UPDATE STATS
   ============================================================ */
function updateStats(history) {
  let safe = 0,
    suspicious = 0,
    malicious = 0;

  history.forEach((item) => {
    if (item.prediction === "safe") safe++;
    else if (item.prediction === "suspicious") suspicious++;
    else if (item.prediction === "malicious") malicious++;
  });

  document.getElementById("safeCount").textContent = safe;
  document.getElementById("suspiciousCount").textContent = suspicious;
  document.getElementById("maliciousCount").textContent = malicious;
}

/* ============================================================
   LOAD HISTORY
   ============================================================ */
async function loadHistory() {
  if (!checkAuth()) return;

  try {
    const response = await fetch(`${API_BASE}/recent-requests`, {
      headers: { "X-API-Key": API_KEY }
    });

    if (!response.ok) return;

    const data = await readJson(response);
    const table = document.getElementById("historyTable");
    table.innerHTML = "";

    if (!data || data.length === 0) {
      table.innerHTML = `
        <tr>
          <td colspan="5" style="text-align:center; color:var(--text-muted); padding:20px;">
            No requests yet. Start analyzing URLs!
          </td>
        </tr>
      `;
      return;
    }

    data.forEach((item) => {
      const predictionClass = `prediction-${item.prediction}`;
      table.innerHTML += `
        <tr id="history-row-${item.id}">
          <td class="url-cell" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</td>
          <td class="${predictionClass}"><strong>${item.prediction.toUpperCase()}</strong></td>
          <td>${formatPercent(item.confidence)}</td>
          <td>${new Date(item.created_at).toLocaleString()}</td>
          <td><button class="btn-secondary btn-small" onclick="toggleHistoryDetails(${item.id})">Open</button></td>
        </tr>
      `;
    });

  } catch (error) {
    console.error("History load error:", error);
  }
}

async function toggleHistoryDetails(historyId) {
  const existing = document.getElementById(`history-detail-${historyId}`);
  if (existing) {
    existing.remove();
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/history/${historyId}`, {
      headers: { "X-API-Key": API_KEY }
    });

    if (!response.ok) {
      alert("Could not load history details.");
      return;
    }

    const data = await readJson(response);
    const row = document.getElementById(`history-row-${historyId}`);
    const detailRow = document.createElement("tr");
    detailRow.id = `history-detail-${historyId}`;
    detailRow.className = "history-detail-row";
    detailRow.innerHTML = `<td colspan="5">${renderHistoryDetail(data)}</td>`;
    row.insertAdjacentElement("afterend", detailRow);
  } catch (error) {
    alert("Error loading history details: " + error.message);
  }
}

function renderHistoryDetail(data) {
  const models = data.model_results || {};
  const modelCards = Object.entries(models).map(([name, item]) => `
    <div class="detail-card">
      <strong>${escapeHtml(name)}</strong>
      <span>${escapeHtml(item.prediction).toUpperCase()}</span>
      <span>Confidence: ${formatPercent(item.confidence)}</span>
      <span>Execution: ${Number(item.execution_time || 0).toFixed(4)}s</span>
    </div>
  `).join("");

  return `
    <div class="history-detail">
      <div class="detail-section">
        <h4>Final Result</h4>
        <p><strong>${escapeHtml(data.final_result || data.prediction).toUpperCase()}</strong> (${formatPercent(data.confidence)})</p>
      </div>
      <div class="detail-section">
        <h4>AI Agent</h4>
        <p>${escapeHtml(data.ai_agent?.explanation || "No AI explanation stored.")}</p>
        <p>${escapeHtml(data.ai_agent?.risk_summary || "")}</p>
        <p>${escapeHtml(data.ai_agent?.human_readable || "")}</p>
      </div>
      <div class="detail-section">
        <h4>VirusTotal</h4>
        <p>Reputation: ${escapeHtml(data.virustotal?.reputation ?? "Unavailable")}</p>
        <p>Detection count: ${escapeHtml(data.virustotal?.detection_count ?? 0)}</p>
        <p>Community score: ${escapeHtml(data.virustotal?.community_score ?? 0)}</p>
      </div>
      <div class="detail-section">
        <h4>Threat Intelligence</h4>
        <p>${escapeHtml(data.threat_intel?.threat_comparison || data.threat_intel?.comparison || "No comparison available")}</p>
        <p>AbuseIPDB: ${escapeHtml(data.threat_intel?.abuseipdb?.listed ? "Listed" : "Clear")}</p>
        <p>OpenPhish: ${escapeHtml(data.threat_intel?.openphish?.listed ? "Listed" : "Clear")}</p>
        <p>URLHaus: ${escapeHtml(data.threat_intel?.urlhaus?.listed ? "Listed" : "Clear")}</p>
      </div>
      <div class="detail-section detail-models">
        <h4>ML Models</h4>
        <div class="detail-grid">${modelCards || "No model results stored."}</div>
      </div>
      <div class="detail-section">
        <h4>Risk Factors</h4>
        <ul>${(data.risk_factors || []).map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
      </div>
      <div class="detail-section">
        <h4>Extracted Features</h4>
        ${featureTable(data.features || data.feature_summary || {})}
      </div>
    </div>
  `;
}

/* ============================================================
   LOAD API KEY INFO
   ============================================================ */
async function loadApiKeyInfo() {
  if (!checkAuth()) return;

  try {
    const response = await fetch(`${API_BASE}/dashboard`, {
      headers: { "X-API-Key": API_KEY }
    });

    if (!response.ok) return;

    const data = await readJson(response);

    document.getElementById("currentApiKeyPrefix").textContent = (data.api_key_prefix || "") + "********";
    document.getElementById("apiUsageTotal").textContent = data.usage_count || 0;
    document.getElementById("apiKeyInput").value = API_KEY || "";

  } catch (error) {
    console.error("API Key info error:", error);
  }
}

/* ============================================================
   API KEY MANAGEMENT
   ============================================================ */
function saveApiKey() {
  const key = document.getElementById("apiKeyInput").value.trim();

  if (!key) {
    alert("Please enter an API Key");
    return;
  }

  API_KEY = key;
  localStorage.setItem("api_key", key);
  alert("✅ API Key saved successfully!");
  loadApiKeyInfo();
}

function clearApiKey() {
  if (!confirm("Are you sure you want to remove the API key?")) return;

  localStorage.removeItem("api_key");
  API_KEY = "";
  document.getElementById("apiKeyInput").value = "";
  alert("🗑 API Key removed");
}

async function regenerateApiKey() {
  if (!API_KEY) {
    alert("Please save an API key first.");
    return;
  }

  if (!confirm("Are you sure you want to regenerate your API key? The old key will stop working immediately.")) {
    return;
  }

  try {
    const response = await fetch(`${API_BASE}/regenerate-key`, {
      method: "POST",
      headers: { "X-API-Key": API_KEY }
    });

    if (!response.ok) {
      const error = await readJson(response).catch(() => ({}));
      alert("Failed to regenerate key: " + (error.detail || response.statusText));
      return;
    }

    const data = await readJson(response);

    API_KEY = data.api_key;
    localStorage.setItem("api_key", API_KEY);
    document.getElementById("apiKeyInput").value = API_KEY;

    alert("✅ New API Key generated!\n\n" + data.api_key + "\n\n⚠️ Save this key now. It won't be shown again.");

    loadApiKeyInfo();

  } catch (error) {
    alert("Error regenerating key: " + error.message);
  }
}

/* ============================================================
   URL ANALYSIS
   ============================================================ */
function fillExample(url) {
  document.getElementById("urlInput").value = url;
  analyzeUrl();
}

async function analyzeUrl() {
  const url = document.getElementById("urlInput").value.trim();
  const useAI = document.getElementById("aiAgentCheck").checked;
  const useIntel = document.getElementById("threatIntelCheck").checked;

  const resultPanel = document.getElementById("resultPanel");
  const loadingEl = document.getElementById("analysisLoading");
  const errorEl = document.getElementById("analysisError");

  resultPanel.style.display = "none";
  errorEl.style.display = "none";

  if (!url) {
    errorEl.textContent = "Please enter a URL.";
    errorEl.style.display = "block";
    return;
  }

  if (!API_KEY) {
    errorEl.textContent = "⚠️ Please save an API key first.";
    errorEl.style.display = "block";
    return;
  }

  loadingEl.style.display = "block";
  const checkBtn = document.querySelector("#section-analysis .btn-primary");
  checkBtn.disabled = true;

  try {
    const response = await fetch(`${API_BASE}/predict`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": API_KEY,
      },
      body: JSON.stringify({
        url: url,
        model_name: "RandomForest",
        use_ai_agent: useAI,
        use_threat_intel: useIntel,
      }),
    });

    if (response.status === 401 || response.status === 403) {
      alert("Invalid API Key.");
      handleLogout();
      return;
    }

    const data = await readJson(response);

    if (!response.ok) {
      throw new Error(data.detail || "Prediction failed");
    }

    renderResults([data], url);

  } catch (error) {
    errorEl.textContent = error.message;
    errorEl.style.display = "block";
  } finally {
    loadingEl.style.display = "none";
    checkBtn.disabled = false;
  }
}

function renderResults(results, url) {
  document.getElementById("resultUrl").textContent = "🔗 " + url;

  const firstResult = results[0];
  const finalPrediction = firstResult.prediction;
  const finalConfidence = firstResult.confidence;
  const ruleOverride = firstResult.rule_override;

  // Domain Status
  const domainStatus = document.getElementById("domainStatus");
  if (firstResult && firstResult.domain_exists !== undefined) {
    if (firstResult.domain_exists) {
      domainStatus.className = "domain-status exists";
      domainStatus.textContent = "Domain exists and is accessible";
    } else {
      domainStatus.className = "domain-status not-exists";
      domainStatus.textContent = "Domain does not exist or DNS resolution failed";
    }
  } else {
    domainStatus.style.display = "none";
  }

  // AI Agent
  const aiBox = document.getElementById("aiAgentBox");
  if (firstResult && firstResult.ai_agent) {
    aiBox.style.display = "block";
    document.getElementById("aiExplanation").textContent = firstResult.ai_agent.explanation;
    document.getElementById("aiRiskSummary").textContent = firstResult.ai_agent.risk_summary || "";
    document.getElementById("aiHumanReadable").textContent = firstResult.ai_agent.human_readable || "";
    const source = firstResult.ai_agent.source;
    document.getElementById("aiSource").textContent = source === "llm" ? "LLM" : "Rule-Based";
    document.getElementById("aiSource").style.color = source === "llm" ? "var(--safe)" : "var(--suspicious)";
  } else {
    aiBox.style.display = "none";
  }

  // Threat Intelligence
  const intelBox = document.getElementById("threatIntelBox");
  if (firstResult && firstResult.threat_intel) {
    intelBox.style.display = "block";
    const intel = firstResult.threat_intel;
    const vt = firstResult.virustotal || intel.virustotal || {};
    document.getElementById("threatComparison").textContent = intel.threat_comparison || intel.comparison || "No comparison available";

    const scanResults = Array.isArray(vt.scan_results)
      ? vt.scan_results.map(item => `${item.category}: ${item.count}`).join(", ")
      : "No scan results";
    document.getElementById("threatDetails").textContent = [
      `VirusTotal reputation: ${vt.reputation ?? "Unavailable"}`,
      `Detection count: ${vt.detection_count ?? 0}`,
      `Community score: ${vt.community_score ?? 0}`,
      `Scan results: ${scanResults}`,
      `AbuseIPDB: ${intel.abuseipdb?.listed ? "Listed" : "Clear"}`,
      `OpenPhish: ${intel.openphish?.listed ? "Listed" : "Clear"}`,
      `URLHaus: ${intel.urlhaus?.listed ? "Listed" : "Clear"}`,
    ].join("\n");
  } else {
    intelBox.style.display = "none";
  }

  // Model Cards
  const grid = document.getElementById("comparisonGrid");
  grid.innerHTML = "";

  if (firstResult && firstResult.model_results) {
    const modelResults = firstResult.model_results;
    const modelNames = Object.keys(modelResults);

    modelNames.forEach((modelName) => {
      const data = modelResults[modelName];
      const card = document.createElement("div");
      card.className = "model-card";
      const pct = Math.round(data.confidence * 100);
      const color = data.prediction === "safe" ? "var(--safe)" :
                    data.prediction === "suspicious" ? "var(--suspicious)" : "var(--malicious)";

      const overrideBadge = ruleOverride ? '<span class="badge-override">⚡ Overridden</span>' : "";

      card.innerHTML = `
        <h3>${modelName} ${overrideBadge}</h3>
        <div class="badge ${data.prediction}">${data.prediction.toUpperCase()}</div>
        <div class="conf-label">
          <span>Confidence</span>
          <span>${pct}%</span>
        </div>
        <div class="conf-bar-bg">
          <div class="conf-bar-fill" style="width:${pct}%; background:${color};"></div>
        </div>
        <div class="domain-age">Execution Time: <strong>${Number(data.execution_time || 0).toFixed(4)}s</strong></div>
        <div class="domain-age">Domain Age: <strong>${firstResult.domain_age ? firstResult.domain_age + " days" : "N/A"}</strong></div>
      `;
      grid.appendChild(card);
    });
  }

  // Consensus
  const consensusEl = document.getElementById("consensus");

  if (ruleOverride) {
    consensusEl.className = "consensus override";
    const emoji = finalPrediction === "malicious" ? "🔴" : "🟡";
    consensusEl.innerHTML = `
      FINAL DECISION: ${emoji} <strong>${finalPrediction.toUpperCase()}</strong>
      <span style="font-weight:400;font-size:13px;display:block;margin-top:4px;">
        Rule engine flagged additional risk. Majority vote remains the final result.
      </span>
    `;
  } else {
    let predictions = [];
    if (firstResult && firstResult.model_results) {
      const modelResults = firstResult.model_results;
      predictions = Object.values(modelResults).map(m => m.prediction);
    } else {
      predictions = results.map(r => r.prediction);
    }

    const unique = [...new Set(predictions)];

    if (unique.length === 1) {
      consensusEl.className = "consensus agreed";
      consensusEl.innerHTML = `FINAL DECISION: <strong>${unique[0].toUpperCase()}</strong> — all models agree`;
    } else if (unique.length === 2) {
      consensusEl.className = "consensus partial";
      const counts = {};
      predictions.forEach(p => counts[p] = (counts[p] || 0) + 1);
      const majority = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
      consensusEl.innerHTML = `FINAL DECISION: <strong>${majority[0].toUpperCase()}</strong> (${majority[1]}/3 majority)`;
    } else {
      consensusEl.className = "consensus disagreed";
      consensusEl.innerHTML = `FINAL DECISION: <strong>${finalPrediction.toUpperCase()}</strong>`;
    }
  }

  // Features
  if (firstResult && firstResult.feature_summary) {
    document.getElementById("featuresGrid").innerHTML = featureTable(firstResult.feature_summary);
  }

  document.getElementById("resultPanel").style.display = "block";
}

function featureTable(features) {
  const rows = Object.entries(features || {}).map(([key, value]) => `
    <tr>
      <td>${escapeHtml(key.replace(/_/g, " "))}</td>
      <td>${escapeHtml(value)}</td>
    </tr>
  `).join("");

  return `
    <div class="table-responsive">
      <table class="feature-table">
        <thead>
          <tr><th>Feature</th><th>Value</th></tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="2">No features available</td></tr>'}</tbody>
      </table>
    </div>
  `;
}

/* ============================================================
   KEYBOARD SHORTCUTS
   ============================================================ */
document.getElementById("urlInput").addEventListener("keydown", (e) => {
  if (e.key === "Enter") analyzeUrl();
});

/* ============================================================
   PAGE LOAD
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  if (!checkAuth()) return;

  loadBackendVersion();

  // Load dashboard by default
  navigateTo("dashboard");
});
