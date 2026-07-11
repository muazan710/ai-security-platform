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
const loginForm = document.getElementById("loginForm");
const signupForm = document.getElementById("signupForm");
const loginMessage = document.getElementById("loginMessage");
const signupMessage = document.getElementById("signupMessage");

/* ============================================================
   TAB SWITCHING
   ============================================================ */
function switchTab(tab) {
  document.querySelectorAll(".auth-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });

  document.querySelectorAll(".auth-form").forEach((form) => {
    form.classList.toggle("active", form.id === `${tab}Form`);
  });

  clearMessages();
}

/* ============================================================
   MESSAGE HELPERS
   ============================================================ */
function showMessage(element, message, type = "error") {
  element.textContent = message;
  element.className = `form-message ${type}`;
}

function clearMessages() {
  [loginMessage, signupMessage].forEach((element) => {
    element.className = "form-message";
    element.textContent = "";
  });
}

/* ============================================================
   VALIDATION HELPERS
   ============================================================ */
function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const type = input.getAttribute("type") === "password" ? "text" : "password";
  input.setAttribute("type", type);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getFieldValue(id) {
  return document.getElementById(id).value.trim();
}

/* ============================================================
   LOGIN
   ============================================================ */
async function handleLogin(event) {
  event.preventDefault();

  const email = getFieldValue("loginEmail");
  const password = getFieldValue("loginPassword");
  clearMessages();

  if (!email || !password) {
    showMessage(loginMessage, "Please fill in all fields.");
    return;
  }

  if (!isValidEmail(email)) {
    showMessage(loginMessage, "Please enter a valid email address.");
    return;
  }

  const submitBtn = loginForm.querySelector(".btn-primary");
  submitBtn.disabled = true;
  submitBtn.textContent = "Logging in...";

  try {
    const response = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await readJson(response);

    if (!response.ok) {
      showMessage(loginMessage, data.detail || "Login failed. Please try again.");
      return;
    }

    if (data.api_key) localStorage.setItem("api_key", data.api_key);
    if (data.access_token) localStorage.setItem("access_token", data.access_token);

    const rememberMe = document.getElementById("rememberMe").checked;
    if (rememberMe) {
      localStorage.setItem("remember_me", "true");
      localStorage.setItem("user_email", email);
    } else {
      localStorage.removeItem("remember_me");
      localStorage.removeItem("user_email");
    }

    window.location.href = "dashboard.html";
  } catch (error) {
    showMessage(loginMessage, "Network error: " + error.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Login";
  }
}

/* ============================================================
   BACKEND VERSION
   ============================================================ */
async function loadBackendVersion() {
  const versionEl = document.getElementById("backendVersion");
  if (!versionEl) return;

  try {
    const response = await fetch(`${API_BASE}/health`);
    if (!response.ok) throw new Error("Health endpoint unavailable");
    const data = await readJson(response);
    versionEl.textContent = data.version ? `Version ${data.version}` : "Version unavailable";
  } catch (error) {
    versionEl.textContent = "Version unavailable";
  }
}

/* ============================================================
   SIGNUP
   ============================================================ */
async function handleSignup(event) {
  event.preventDefault();

  const fullName = getFieldValue("signupName");
  const email = getFieldValue("signupEmail");
  const password = getFieldValue("signupPassword");
  const confirmPassword = getFieldValue("signupConfirmPassword");
  clearMessages();

  if (!fullName) {
    showMessage(signupMessage, "Please enter your full name.");
    return;
  }

  if (!email || !isValidEmail(email)) {
    showMessage(signupMessage, "Please enter a valid email address.");
    return;
  }

  if (!password) {
    showMessage(signupMessage, "Please enter a password.");
    return;
  }

  if (password.length < 8) {
    showMessage(signupMessage, "Password must be at least 8 characters.");
    return;
  }

  if (password !== confirmPassword) {
    showMessage(signupMessage, "Passwords do not match.");
    return;
  }

  const submitBtn = signupForm.querySelector(".btn-primary");
  submitBtn.disabled = true;
  submitBtn.textContent = "Creating Account...";

  try {
    const response = await fetch(`${API_BASE}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, full_name: fullName }),
    });
    const data = await readJson(response);

    if (!response.ok) {
      showMessage(signupMessage, data.detail || "Signup failed. Please try again.");
      return;
    }

    if (data.api_key) {
      localStorage.setItem("api_key", data.api_key);
    }
    localStorage.setItem("user_email", email);
    showMessage(signupMessage, data.message || "Account created successfully.", "success");
    setTimeout(() => {
      window.location.href = "dashboard.html";
    }, 800);
  } catch (error) {
    showMessage(signupMessage, "Network error: " + error.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Create Account";
  }
}

/* ============================================================
   KEYBOARD SHORTCUTS
   ============================================================ */
document.getElementById("loginPassword").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    handleLogin(event);
  }
});

document.getElementById("signupConfirmPassword").addEventListener("keydown", (event) => {
  if (event.key === "Enter") {
    event.preventDefault();
    handleSignup(event);
  }
});

/* ============================================================
   PAGE LOAD
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  loadBackendVersion();

  const rememberMe = localStorage.getItem("remember_me");
  const userEmail = localStorage.getItem("user_email");

  if (rememberMe && userEmail) {
    document.getElementById("loginEmail").value = userEmail;
    document.getElementById("rememberMe").checked = true;
  }

  const apiKey = localStorage.getItem("api_key");
  if (apiKey && !window.location.pathname.includes("dashboard.html")) {
    window.location.href = "dashboard.html";
  }
});

/* ============================================================
   GLOBALS
   ============================================================ */
window.switchTab = switchTab;
window.togglePassword = togglePassword;
window.handleLogin = handleLogin;
window.handleSignup = handleSignup;
