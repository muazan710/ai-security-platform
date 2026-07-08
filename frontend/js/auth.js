/* ============================================================
   CONFIGURATION
   ============================================================ */
function resolveApiBase() {
  if (window.API_BASE) return window.API_BASE;
  const savedBase = localStorage.getItem("api_base");
  if (savedBase) return savedBase;

  const { protocol, hostname, port, origin } = window.location;
  if (protocol === "file:" || port === "5500" || port === "3000") {
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
  // Update tab buttons
  document.querySelectorAll(".auth-tab").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.tab === tab);
  });

  // Update forms
  document.querySelectorAll(".auth-form").forEach((form) => {
    form.classList.toggle("active", form.id === (tab === "login" ? "loginForm" : "signupForm"));
  });

  // Clear messages
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
  loginMessage.className = "form-message";
  loginMessage.textContent = "";
  signupMessage.className = "form-message";
  signupMessage.textContent = "";
}

/* ============================================================
   TOGGLE PASSWORD
   ============================================================ */
function togglePassword(inputId) {
  const input = document.getElementById(inputId);
  const type = input.getAttribute("type") === "password" ? "text" : "password";
  input.setAttribute("type", type);
}

/* ============================================================
   VALIDATION HELPERS
   ============================================================ */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function getFieldValue(id) {
  return document.getElementById(id).value.trim();
}

/* ============================================================
   HANDLE LOGIN
   ============================================================ */
async function handleLogin(event) {
  event.preventDefault();

  const email = getFieldValue("loginEmail");
  const password = getFieldValue("loginPassword");

  // Clear previous messages
  clearMessages();

  // Validation
  if (!email || !password) {
    showMessage(loginMessage, "Please fill in all fields.");
    return;
  }

  if (!isValidEmail(email)) {
    showMessage(loginMessage, "Please enter a valid email address.");
    return;
  }

  // Disable button
  const submitBtn = loginForm.querySelector(".btn-primary");
  submitBtn.disabled = true;
  submitBtn.textContent = "Logging in...";

  try {
    const response = await fetch(`${API_BASE}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ email, password }),
    });

    const data = await readJson(response);

    if (!response.ok) {
      showMessage(loginMessage, data.detail || "Login failed. Please try again.");
      return;
    }

    // Save tokens to localStorage
    if (data.api_key) {
      localStorage.setItem("api_key", data.api_key);
    }

    if (data.access_token) {
      localStorage.setItem("access_token", data.access_token);
    }

    // Remember Me
    const rememberMe = document.getElementById("rememberMe").checked;
    if (rememberMe) {
      localStorage.setItem("remember_me", "true");
      localStorage.setItem("user_email", email);
    } else {
      localStorage.removeItem("remember_me");
      localStorage.removeItem("user_email");
    }

    // Redirect to dashboard
    window.location.href = "dashboard.html";

  } catch (error) {
    showMessage(loginMessage, "Network error: " + error.message);
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Login";
  }
}

/* ============================================================
   HANDLE SIGNUP
   ============================================================ */
async function handleSignup(event) {
  event.preventDefault();

  const fullName = getFieldValue("signupName");
  const email = getFieldValue("signupEmail");
  const password = getFieldValue("signupPassword");
  const confirmPassword = getFieldValue("signupConfirmPassword");

  // Clear previous messages
  clearMessages();

  // Validation
  if (!fullName) {
    showMessage(signupMessage, "Please enter your full name.");
    return;
  }

  if (!email) {
    showMessage(signupMessage, "Please enter your email address.");
    return;
  }

  if (!isValidEmail(email)) {
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

  // Disable button
  const submitBtn = signupForm.querySelector(".btn-primary");
  submitBtn.disabled = true;
  submitBtn.textContent = "Creating Account...";

  try {
    const response = await fetch(`${API_BASE}/signup`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email,
        password,
        full_name: fullName,
      }),
    });

    const data = await readJson(response);

    if (!response.ok) {
      showMessage(signupMessage, data.detail || "Signup failed. Please try again.");
      return;
    }

    // Show success message
    showMessage(signupMessage, "✅ Account created successfully! Please login.", "success");

    // Clear form
    document.getElementById("signupName").value = "";
    document.getElementById("signupEmail").value = "";
    document.getElementById("signupPassword").value = "";
    document.getElementById("signupConfirmPassword").value = "";

    // Switch to login tab after 1.5 seconds
    setTimeout(() => {
      switchTab("login");
      // Pre-fill email
      document.getElementById("loginEmail").value = email;
    }, 1500);

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
// Login with Enter key
document.getElementById("loginPassword").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    handleLogin(e);
  }
});

// Signup with Enter key (on confirm password)
document.getElementById("signupConfirmPassword").addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    e.preventDefault();
    handleSignup(e);
  }
});

/* ============================================================
   REMEMBER ME ON PAGE LOAD
   ============================================================ */
document.addEventListener("DOMContentLoaded", () => {
  const rememberMe = localStorage.getItem("remember_me");
  const userEmail = localStorage.getItem("user_email");

  if (rememberMe && userEmail) {
    document.getElementById("loginEmail").value = userEmail;
    document.getElementById("rememberMe").checked = true;
  }

  // If already logged in, redirect to dashboard
  const apiKey = localStorage.getItem("api_key");
  if (apiKey) {
    // Only redirect if we're on the auth page and have a valid API key
    // This prevents redirect loop on dashboard page
    if (!window.location.pathname.includes("dashboard.html")) {
      window.location.href = "dashboard.html";
    }
  }
});

/* ============================================================
   EXPOSE FUNCTIONS TO GLOBAL SCOPE
   ============================================================ */
window.switchTab = switchTab;
window.togglePassword = togglePassword;
window.handleLogin = handleLogin;
window.handleSignup = handleSignup;
