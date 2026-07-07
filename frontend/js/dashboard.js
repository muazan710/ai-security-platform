/* ============================================================
   CONFIGURATION
   ============================================================ */
const API_BASE = "http://127.0.0.1:8000";
const MODELS = ["RandomForest", "LogisticRegression", "XGBoost"];
let API_KEY = localStorage.getItem("api_key") || "";

/* ============================================================
   DOM REFERENCES
   ============================================================ */
const sections = {
  dashboard: document.getElementById("section-dashboard"),
  analysis: document.getElementById("section-analysis"),
  history: document.getElementById("section-history"),
  apiKey: document.getElementById("section-api-key"),
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
    apiKey: "API Key Management",
  };
  document.getElementById("pageTitle").textContent = titles[section] || "Dashboard";

  // Load data based on section
  if (section === "dashboard") {
    loadDashboard();
  } else if (section === "history") {
    loadHistory();
  } else if (section === "apiKey") {
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

    const data = await response.json();

    // Update stats
    document.getElementById("totalRequests").textContent = data.usage_count || 0;
    document.getElementById("profileEmail").textContent = data.email || "-";
    document.getElementById("profileApiKey").textContent = (data.api_key_prefix || "") + "********";
    document.getElementById("profileUsage").textContent = data.usage_count || 0;
    document.getElementById("profileLastLogin").textContent = data.last_login ? new Date(data.last_login).toLocaleString() : "-";
    document.getElementById("profileCreated").textContent = data.created_at ? new Date(data.created_at).toLocaleString() : "-";

    updateUserInfo(data);

    // Load recent activity
    loadRecentActivity();

  } catch (error) {
    console.error("Dashboard error:", error);
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

    const data = await response.json();
    const container = document.getElementById("recentActivity");

    if (!data || data.length === 0) {
      container.innerHTML = '<p class="text-muted">No recent activity yet.</p>';
      return;
    }

    // Show last 5 requests
    const recent = data.slice(0, 5);
    let html = '<div style="display:flex;flex-direction:column;gap:8px;">';
    recent.forEach((item) => {
      const color = item.prediction === "safe" ? "var(--safe)" :
                    item.prediction === "suspicious" ? "var(--suspicious)" : "var(--malicious)";
      html += `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#0d1420;border-radius:6px;flex-wrap:wrap;gap:8px;">
          <span style="font-size:13px;color:var(--text-primary);word-break:break-all;flex:1;">${item.url}</span>
          <span style="font-size:12px;font-weight:600;color:${color};">${item.prediction.toUpperCase()}</span>
          <span style="font-size:11px;color:var(--text-muted);">${new Date(item.created_at).toLocaleString()}</span>
        </div>
      `;
    });
    html += '</div>';
    container.innerHTML = html;

    // Update stats
    updateStats(data);

  } catch (error) {
    console.error("Recent activity error:", error);
  }
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

    const data = await response.json();
    const table = document.getElementById("historyTable");
    table.innerHTML = "";

    if (!data || data.length === 0) {
      table.innerHTML = `
        <tr>
          <td colspan="4" style="text-align:center; color:var(--text-muted); padding:20px;">
            No requests yet. Start analyzing URLs!
          </td>
        </tr>
      `;
      return;
    }

    data.forEach((item) => {
      const predictionClass = `prediction-${item.prediction}`;
      table.innerHTML += `
        <tr>
          <td class="url-cell" title="${item.url}">${item.url}</td>
          <td class="${predictionClass}"><strong>${item.prediction.toUpperCase()}</strong></td>
          <td>${(item.confidence * 100).toFixed(1)}%</td>
          <td>${new Date(item.created_at).toLocaleString()}</td>
        </tr>
      `;
    });

  } catch (error) {
    console.error("History load error:", error);
  }
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

    const data = await response.json();

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
      const error = await response.json().catch(() => ({}));
      alert("Failed to regenerate key: " + (error.detail || response.statusText));
      return;
    }

    const data = await response.json();

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

  const results = [];
  let errors = [];
  let domainNotFound = false;

  try {
    const promises = MODELS.map(async (model) => {
      try {
        const response = await fetch(`${API_BASE}/predict`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
          },
          body: JSON.stringify({
            url,
            model_name: model,
            use_ai_agent: useAI,
            use_threat_intel: useIntel,
          }),
        });

        if (response.status === 404) {
          domainNotFound = true;
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.detail || "Domain does not exist");
        }

        if (response.status === 401 || response.status === 403) {
          alert("Invalid API Key. Please login again.");
          handleLogout();
          throw new Error("Authentication failed");
        }

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.detail || `Server error (${response.status})`);
        }

        return await response.json();
      } catch (error) {
        errors.push(`${model}: ${error.message}`);
        return null;
      }
    });

    const allResults = await Promise.all(promises);
    allResults.forEach((data) => {
      if (data) results.push(data);
    });

    if (domainNotFound) {
      errorEl.textContent = "❌ Domain does not exist. Please check the URL.";
      errorEl.style.display = "block";
      loadingEl.style.display = "none";
      checkBtn.disabled = false;
      return;
    }

    if (results.length === 0) {
      errorEl.textContent = "❌ All models failed. " + errors.join(" | ");
      errorEl.style.display = "block";
      return;
    }

    renderResults(results, url);

  } catch (error) {
    errorEl.textContent = "❌ Error: " + error.message;
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
      domainStatus.textContent = "✅ Domain exists and is accessible";
    } else {
      domainStatus.className = "domain-status not-exists";
      domainStatus.textContent = "❌ Domain does NOT exist (DNS resolution failed - URL is invalid or misspelled)";
    }
  } else {
    domainStatus.style.display = "none";
  }

  // AI Agent
  const aiBox = document.getElementById("aiAgentBox");
  if (firstResult && firstResult.ai_agent) {
    aiBox.style.display = "block";
    document.getElementById("aiExplanation").textContent = firstResult.ai_agent.explanation;
    const source = firstResult.ai_agent.source;
    document.getElementById("aiSource").textContent = source === "llm" ? "🤖 LLM" : "🧠 Rule-Based";
    document.getElementById("aiSource").style.color = source === "llm" ? "var(--safe)" : "var(--suspicious)";
  } else {
    aiBox.style.display = "none";
  }

  // Threat Intelligence
  const intelBox = document.getElementById("threatIntelBox");
  if (firstResult && firstResult.threat_intel) {
    intelBox.style.display = "block";
    const intel = firstResult.threat_intel;
    document.getElementById("threatComparison").textContent = intel.comparison || "No comparison available";

    let details = "";
    if (intel.virustotal && !intel.virustotal.error) {
      const vt = intel.virustotal;
      details += `🦠 VirusTotal: ${vt.detection_ratio || "N/A"} engines flagged malicious | Reputation: ${vt.reputation || "N/A"}`;
    }
    if (intel.threat_feeds && intel.threat_feeds.length > 0) {
      details += `\n📋 Threat Feeds: ${intel.threat_feeds.join("; ")}`;
    }
    document.getElementById("threatDetails").textContent = details || "No additional threat data";
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
        <div class="domain-age">
          🌐 Domain Age: <strong>${firstResult.domain_age ? firstResult.domain_age + " days" : "N/A"}</strong>
        </div>
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
      ${emoji} <strong>${finalPrediction.toUpperCase()}</strong>
      <span style="font-weight:400;font-size:13px;display:block;margin-top:4px;">
        ⚠️ Rule-Based Override Active — ML models overridden by security rules
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
      consensusEl.innerHTML = `✅ ALL MODELS AGREE: <strong>${unique[0].toUpperCase()}</strong>`;
    } else if (unique.length === 2) {
      consensusEl.className = "consensus partial";
      const counts = {};
      predictions.forEach(p => counts[p] = (counts[p] || 0) + 1);
      const majority = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
      consensusEl.innerHTML = `⚠️ PARTIAL: ${majority[0].toUpperCase()} (${majority[1]}/3) — Models disagree`;
    } else {
      consensusEl.className = "consensus disagreed";
      consensusEl.innerHTML = `❌ NO CONSENSUS — Manual review recommended`;
    }
  }

  // Features
  if (firstResult && firstResult.feature_summary) {
    const grid2 = document.getElementById("featuresGrid");
    grid2.innerHTML = "";
    Object.entries(firstResult.feature_summary).forEach(([k, v]) => {
      if (k !== "domain_age_days" && k !== "domain_exists" && k !== "rule_override") {
        const div = document.createElement("div");
        div.innerHTML = `${k.replace(/_/g, " ")}: <span>${v}</span>`;
        grid2.appendChild(div);
      }
    });
  }

  document.getElementById("resultPanel").style.display = "block";
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

  // Load dashboard by default
  navigateTo("dashboard");
});
