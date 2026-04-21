const BACKEND_BASE_URL = 'http://127.0.0.1:5501';
const API_BASE_URL = (() => {
  const origin = window.location.origin;
  const backendOrigins = [BACKEND_BASE_URL, 'http://localhost:5501'];
  if (backendOrigins.includes(origin)) {
    return origin;
  }
  return BACKEND_BASE_URL;
})();

// Make API_BASE_URL available globally for HTML files
window.API_BASE_URL = API_BASE_URL;

let users = loadUsers();
let loginAttempts = {};
let maxAttempts = 3;
let generatedOTP = "";
let otpTime = 30;
let otpExpireTS = 0;

const notificationStorageKey = 'dashboardNotifications';
const securityLogStorageKey = 'securityEventLog';
const sessionExpiryKey = 'sessionExpiryTimestamp';
const INACTIVITY_TIMEOUT_MS = 30 * 60 * 1000; // 30 minutes

let loginChartLabels = ['6d', '5d', '4d', '3d', '2d', '1d', 'Today'];
let loginChartData = [2, 3, 1, 4, 5, 2, 6];
let chartUpdateInterval;
let loginChartInstance = null;

function loadUsers() {
  let saved = localStorage.getItem("users");
  return saved ? JSON.parse(saved) : [];
}

function saveUsers() {
  localStorage.setItem("users", JSON.stringify(users));
}

// DASHBOARD SEARCH FUNCTIONALITY
function searchDashboard() {
  const query = document.getElementById('searchInput').value.toLowerCase();
  const sections = document.querySelectorAll('.section');

  sections.forEach(section => {
    const text = section.textContent.toLowerCase();
    const h3 = section.querySelector('h3');
    if (h3) {
      const title = h3.textContent.toLowerCase();
      if (text.includes(query) || title.includes(query) || query === '') {
        section.style.display = 'block';
      } else {
        section.style.display = 'none';
      }
    }
  });
}

// SETTINGS PANEL TOGGLE
function toggleSettings() {
  const panel = document.getElementById('settingsPanel');
  const profilePanel = document.getElementById('profilePanel');

  if (panel.style.display === 'none' || panel.style.display === '') {
    panel.style.display = 'block';
    profilePanel.style.display = 'none';
    loadSettings();
  } else {
    panel.style.display = 'none';
  }
}

// LOAD SETTINGS FROM LOCALSTORAGE
function loadSettings() {
  const settings = JSON.parse(localStorage.getItem('securitySettings') || '{}');

  document.getElementById('requireUppercase').checked = settings.requireUppercase !== false;
  document.getElementById('requireNumbers').checked = settings.requireNumbers !== false;
  document.getElementById('requireSpecial').checked = settings.requireSpecial !== false;
  document.getElementById('minPasswordLength').value = settings.minPasswordLength || 10;
  document.getElementById('sessionTimeout').value = settings.sessionTimeout || 30;
  document.getElementById('maxLoginAttempts').value = settings.maxLoginAttempts || 3;
}

// SAVE SETTINGS TO LOCALSTORAGE
function saveSettings() {
  const settings = {
    requireUppercase: document.getElementById('requireUppercase').checked,
    requireNumbers: document.getElementById('requireNumbers').checked,
    requireSpecial: document.getElementById('requireSpecial').checked,
    minPasswordLength: parseInt(document.getElementById('minPasswordLength').value),
    sessionTimeout: parseInt(document.getElementById('sessionTimeout').value),
    maxLoginAttempts: parseInt(document.getElementById('maxLoginAttempts').value)
  };

  localStorage.setItem('securitySettings', JSON.stringify(settings));
  notify('Security settings saved successfully!', 'success');
  toggleSettings();
}

// AUTHENTICATION OVERVIEW FUNCTIONS
async function loadAuthOverview() {
  try {
    // Get total users with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    const usersResponse = await fetch(`${API_BASE_URL}/get-users`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('sessionToken')}` },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (usersResponse.ok) {
      const contentType = usersResponse.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        throw new Error("Response is not JSON");
      }
      const users = await usersResponse.json();
      document.getElementById('totalUsers').textContent = users.length;
    } else {
      console.warn('Failed to load users for auth overview, status:', usersResponse.status);
      document.getElementById('totalUsers').textContent = '--';
    }

    // Get active sessions (simulated for now)
    document.getElementById('activeSessions').textContent = '1'; // Current user

    // Get failed attempts from localStorage
    const failedAttempts = JSON.parse(localStorage.getItem('failedLoginAttempts') || '[]');
    const recentFailures = failedAttempts.filter(attempt =>
      Date.now() - attempt.timestamp < 24 * 60 * 60 * 1000
    ).length;
    document.getElementById('failedAttempts').textContent = recentFailures;

  } catch (error) {
    console.error('Error loading auth overview:', error);
    // Set fallback values
    document.getElementById('totalUsers').textContent = '--';
    document.getElementById('activeSessions').textContent = '--';
    document.getElementById('failedAttempts').textContent = '--';
  }
}

// SECURITY ALERTS MANAGEMENT
function loadSecurityAlerts() {
  const alerts = JSON.parse(localStorage.getItem('securityAlerts') || '[]');
  const container = document.getElementById('alertsContainer');

  if (alerts.length === 0) {
    container.innerHTML = '<p class="no-alerts">No security alerts at this time.</p>';
    return;
  }

  container.innerHTML = alerts.map(alert => `
    <div class="alert-item ${alert.type}">
      <p>${alert.icon} ${alert.message}</p>
      <small>${new Date(alert.timestamp).toLocaleString()}</small>
    </div>
  `).join('');
}

function addSecurityAlert(type, message, icon = '⚠️') {
  const alerts = JSON.parse(localStorage.getItem('securityAlerts') || '[]');
  alerts.unshift({
    type,
    message,
    icon,
    timestamp: Date.now()
  });

  // Keep only last 50 alerts
  if (alerts.length > 50) alerts.splice(50);

  localStorage.setItem('securityAlerts', JSON.stringify(alerts));
  loadSecurityAlerts();
}

function clearAlerts() {
  localStorage.setItem('securityAlerts', '[]');
  loadSecurityAlerts();
  notify('All alerts cleared!', 'success');
}

// USER MANAGEMENT FUNCTIONS
async function loadUsers() {
  try {
    // Add timeout to prevent hanging
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    const response = await fetch(`${API_BASE_URL}/get-users`, {
      method: 'GET',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('sessionToken')}` },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      const contentType = response.headers.get("content-type");
      if (!contentType || !contentType.includes("application/json")) {
        throw new Error("Response is not JSON");
      }
      const users = await response.json();
      console.log('Loaded users:', users);
      displayUsers(users);
    } else {
      console.warn('Failed to load users from backend, status:', response.status);
      // Fallback to demo users if endpoint doesn't exist
      const demoUsers = [
        { user: 'admin', email: 'admin@example.com', role: 'admin', status: 'active' },
        { user: 'demouser', email: 'demo@gmail.com', role: 'user', status: 'active' }
      ];
      displayUsers(demoUsers);
    }
  } catch (error) {
    console.error('Error loading users:', error);
    // Fallback to demo users
    const demoUsers = [
      { user: 'admin', email: 'admin@example.com', role: 'admin', status: 'active' },
      { user: 'demouser', email: 'demo@gmail.com', role: 'user', status: 'active' }
    ];
    displayUsers(demoUsers);
  }
}

function displayUsers(users) {
  const tbody = document.getElementById('userTableBody');
  tbody.innerHTML = users.map(user => `
    <tr>
      <td>${user.user}</td>
      <td>${user.email}</td>
      <td><span class="role-badge ${user.role}">${user.role}</span></td>
      <td><span class="status-badge ${user.status || 'active'}">${user.status || 'active'}</span></td>
      <td>
        <button onclick="editUser('${user.user}')" class="small-btn">Edit</button>
        <button onclick="deleteUser('${user.user}')" class="small-btn danger">Delete</button>
      </td>
    </tr>
  `).join('');
}

function filterUsers() {
  const query = document.getElementById('userSearch').value.toLowerCase();
  const rows = document.querySelectorAll('#userTableBody tr');

  rows.forEach(row => {
    const text = row.textContent.toLowerCase();
    row.style.display = text.includes(query) ? '' : 'none';
  });
}

function showAddUserModal() {
  document.getElementById('addUserModal').style.display = 'block';
}

function closeModal() {
  document.getElementById('addUserModal').style.display = 'none';
  // Clear form
  document.getElementById('newUserUsername').value = '';
  document.getElementById('newUserEmail').value = '';
  document.getElementById('newUserPassword').value = '';
}

async function addUser() {
  const username = document.getElementById('newUserUsername').value.trim();
  const email = document.getElementById('newUserEmail').value.trim();
  const password = document.getElementById('newUserPassword').value;
  const role = document.getElementById('newUserRole').value;

  if (!username || !email || !password) {
    alert('All fields are required!');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/admin/add-user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('sessionToken')}`
      },
      body: JSON.stringify({ username, email, password, role })
    });

    if (response.ok) {
      notify('User added successfully!', 'success');
      closeModal();
      loadUsers();
      loadAuthOverview(); // Update total users count
    } else {
      const data = await response.json();
      alert(data.error || 'Failed to add user');
    }
  } catch (error) {
    console.error('Error adding user:', error);
    alert('Error adding user. Check console.');
  }
}

async function deleteUser(username) {
  if (!confirm(`Are you sure you want to delete user "${username}"?`)) {
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/admin/delete-user`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('sessionToken')}`
      },
      body: JSON.stringify({ username })
    });

    if (response.ok) {
      notify('User deleted successfully!', 'success');
      loadUsers();
      loadAuthOverview(); // Update total users count
    } else {
      const data = await response.json();
      alert(data.error || 'Failed to delete user');
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    alert('Error deleting user. Check console.');
  }
}

function editUser(username) {
  alert(`Edit user functionality for "${username}" - Coming soon!`);
  // TODO: Implement edit user modal
}

// ENHANCED MFA FUNCTIONS
function loadMFAStatus() {
  const mfaEnabled = localStorage.getItem("mfaEnabled") === "true";
  const mfaMethod = localStorage.getItem("mfaMethod") || "otp";

  document.getElementById('mfaStatus').textContent = mfaEnabled ? 'Enabled' : 'Disabled';
  document.getElementById('mfaToggleBtn').textContent = mfaEnabled ? 'Disable MFA' : 'Enable MFA';

  // Set radio button
  document.querySelector(`input[name="mfaMethod"][value="${mfaMethod}"]`).checked = true;
}

function toggleMFA() {
  const currentlyEnabled = localStorage.getItem("mfaEnabled") === "true";
  const selectedMethod = document.querySelector('input[name="mfaMethod"]:checked').value;

  if (!currentlyEnabled) {
    // Enable MFA
    localStorage.setItem("mfaEnabled", "true");
    localStorage.setItem("mfaMethod", selectedMethod);
    notify(`MFA enabled with ${selectedMethod.toUpperCase()}!`, 'success');
    addSecurityAlert('success', `Multi-factor authentication enabled using ${selectedMethod}`, '🔐');
  } else {
    // Disable MFA
    if (confirm('Are you sure you want to disable MFA? This will reduce your account security.')) {
      localStorage.setItem("mfaEnabled", "false");
      notify('MFA disabled!', 'warning');
      addSecurityAlert('warning', 'Multi-factor authentication disabled', '⚠️');
    }
  }

  loadMFAStatus();
}

// VULNERABILITY MONITORING
function loadVulnerabilityStatus() {
  // Simulate vulnerability monitoring
  const threatLevel = calculateThreatLevel();
  document.getElementById('threatLevel').textContent = threatLevel.level;
  document.getElementById('threatLevel').className = `threat-${threatLevel.class}`;
}

function calculateThreatLevel() {
  const failedAttempts = JSON.parse(localStorage.getItem('failedLoginAttempts') || '[]');
  const recentFailures = failedAttempts.filter(attempt =>
    Date.now() - attempt.timestamp < 60 * 60 * 1000 // Last hour
  ).length;

  if (recentFailures > 10) return { level: 'HIGH', class: 'high' };
  if (recentFailures > 5) return { level: 'MEDIUM', class: 'medium' };
  return { level: 'LOW', class: 'low' };
}

function runSecurityScan() {
  notify('Running security scan...', 'info');

  // Simulate security scan
  setTimeout(() => {
    const vulnerabilities = checkForVulnerabilities();
    if (vulnerabilities.length > 0) {
      addSecurityAlert('warning', `Security scan found ${vulnerabilities.length} potential issues`, '🔍');
      notify(`Security scan complete. Found ${vulnerabilities.length} issues.`, 'warning');
    } else {
      addSecurityAlert('success', 'Security scan completed - No vulnerabilities found', '✅');
      notify('Security scan complete - System secure!', 'success');
    }
  }, 2000);
}

function checkForVulnerabilities() {
  const issues = [];

  // Check password strength
  const currentPass = getCurrentPassword();
  if (currentPass.length < 10) {
    issues.push('Weak password detected');
  }

  // Check MFA status
  if (localStorage.getItem("mfaEnabled") !== "true") {
    issues.push('MFA not enabled');
  }

  // Check for old sessions
  const lastActivity = parseInt(localStorage.getItem('lastActivity') || '0');
  if (Date.now() - lastActivity > 24 * 60 * 60 * 1000) {
    issues.push('Account inactive for 24+ hours');
  }

  return issues;
}

// ACTIVITY TABS
function showTab(tabName) {
  // Hide all tabs
  document.getElementById('notificationsTab').style.display = 'none';
  document.getElementById('activityTab').style.display = 'none';

  // Remove active class from all buttons
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));

  // Show selected tab
  document.getElementById(tabName + 'Tab').style.display = 'block';

  // Add active class to clicked button
  event.target.classList.add('active');
}

// UPDATE CHART WITH TIME RANGE
function updateChart() {
  const timeRange = document.getElementById('timeRange').value;
  let days, labels, data;

  switch(timeRange) {
    case '7d':
      days = 7;
      labels = ['6d', '5d', '4d', '3d', '2d', '1d', 'Today'];
      data = [2, 3, 1, 4, 5, 2, 6];
      break;
    case '30d':
      days = 30;
      labels = Array.from({length: 30}, (_, i) => `${30-i}d ago`);
      data = Array.from({length: 30}, () => Math.floor(Math.random() * 10) + 1);
      break;
    case '90d':
      days = 90;
      labels = Array.from({length: 90}, (_, i) => `${90-i}d ago`);
      data = Array.from({length: 90}, () => Math.floor(Math.random() * 8) + 1);
      break;
  }

  loginChartLabels = labels;
  loginChartData = data;

  if (loginChartInstance) {
    loginChartInstance.data.labels = labels;
    loginChartInstance.data.datasets[0].data = data;
    loginChartInstance.update();
  }
}

// PASSWORD STRENGTH
function checkStrength() {
  let pass = document.getElementById("regPass").value;
  let msg = document.getElementById("strengthMsg");

  if (pass.length < 6) msg.innerText = "Weak Password";
  else if (pass.match(/[A-Z]/) && pass.match(/[0-9]/)) msg.innerText = "Strong Password";
  else msg.innerText = "Medium Password";
}

// TOGGLE PASSWORD VISIBILITY
function togglePassword() {
  const passwordField = document.getElementById('password');
  if (passwordField.type === 'password') {
    passwordField.type = 'text';
  } else {
    passwordField.type = 'password';
  }
}

// REGISTER - Now sends data to backend
async function register() {
  let user = sanitizeInput(document.getElementById("regUser").value.trim());
  let email = sanitizeInput(document.getElementById("regEmail").value.trim());
  let pass = document.getElementById("regPass").value;
  let confirm = document.getElementById("regConfirm").value;

  if (!user || !email || !pass || !confirm) {
    document.getElementById("regError").innerText = "All fields required!";
    return;
  }

  if (pass !== confirm) {
    document.getElementById("regError").innerText = "Passwords do not match!";
    return;
  }

  if (pass.length < 10 || !/[A-Z]/.test(pass) || !/[0-9]/.test(pass) || !/[^A-Za-z0-9]/.test(pass)) {
    document.getElementById("regError").innerText = "Use strong password: >=10 chars, uppercase, digits, special chars.";
    return;
  }

  // Send registration to backend
  try {
    const response = await fetch(`${API_BASE_URL}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, email, pass })
    });
    const data = await response.json();

    if (response.ok) {
      alert("Registered successfully!");
      window.location.href = "login.html";
    } else {
      document.getElementById("regError").innerText = data.error || "Registration failed!";
    }
  } catch (error) {
    console.error(error);
    document.getElementById("regError").innerText = "Unable to reach backend server. Make sure the backend is running on port 5501.";
  }
}

// LOGIN - Now authenticates with backend
async function login() {
  let user = document.getElementById("username").value.trim();
  let pass = document.getElementById("password").value;

  if (!user || !pass) {
    document.getElementById("errorMsg").innerText = "Both fields are required!";
    return;
  }

  loginAttempts[user] = loginAttempts[user] || 0;
  if (loginAttempts[user] >= maxAttempts) {
    document.getElementById("lockMsg").innerText = "Account locked after 3 wrong attempts!";
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, pass })
    });
    const data = await response.json();

    if (response.ok) {
      loginAttempts[user] = 0;
      // Store only username temporarily to identify user for OTP
      localStorage.setItem("tempUsername", user);
      // Set OTP expiration time (30 seconds from now)
      localStorage.setItem("otpExpireTS", (Date.now() + 30 * 1000).toString());
      logSecurityEvent('LoginSuccess', `User ${sanitizeInput(user)} logged in.`);
      notify("Login successful! Check your email for OTP", 'success');
      window.location.href = "otp.html";
    } else {
      loginAttempts[user]++;
      document.getElementById("errorMsg").innerText = data.error + " Attempts: " + loginAttempts[user];
      logSecurityEvent('LoginFailure', `Failed login attempt for ${sanitizeInput(user)} (attempt ${loginAttempts[user]})`);
      notify("Login failed for user " + user, 'error');
    }
  } catch (error) {
    console.error(error);
    document.getElementById("errorMsg").innerText = "Unable to reach backend server. Make sure the backend is running on port 5501.";
  }
}

// Google-style login button (simulate OAuth by asking gmail user)
async function googleLogin() {
  const email = prompt("Enter your Google email (e.g. user@gmail.com):");
  if (!email || !email.endsWith("@gmail.com")) {
    alert("Please enter a valid Gmail address.");
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/google-login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email })
    });
    const data = await response.json();

    if (response.ok) {
      localStorage.setItem("tempUsername", data.username);
      alert("OTP sent to " + email + ". Check your inbox.");
      window.location.href = "otp.html";
    } else {
      alert(data.error || 'Google login failed');
    }
  } catch (error) {
    console.error(error);
    alert('Error connecting to server for Google login.');
  }
}

// OTP is now handled by backend /login endpoint
// This function is no longer needed but kept for reference

// OTP TIMER
function startOTP() {
  let timerEl = document.getElementById("timer");
  if (!timerEl) return;

  let expire = parseInt(localStorage.getItem("otpExpireTS") || "0", 10);

  if (!expire || Date.now() > expire) {
    timerEl.innerText = "OTP expired. Please resend OTP.";
    return;
  }

  let interval = setInterval(() => {
    let remaining = Math.max(0, Math.floor((expire - Date.now()) / 1000));
    timerEl.innerText = "OTP expires in " + remaining + " sec";

    if (remaining <= 0) {
      timerEl.innerText = "OTP expired. Please resend OTP.";
      clearInterval(interval);
    }
  }, 1000);
}

// VERIFY OTP - Now authenticates with backend
async function verifyOTP() {
  let otp = document.getElementById("otp").value.trim();
  const user = localStorage.getItem("tempUsername");

  if (!otp) {
    document.getElementById("otpError").innerText = "OTP required.";
    logSecurityEvent('OTPFailure', 'OTP entry missing.');
    return;
  }

  if (!user) {
    document.getElementById("otpError").innerText = "User session not found. Please login again.";
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, otp })
    });
    const data = await response.json();

    if (response.ok) {
      // OTP verified, store session token (not user data)
      localStorage.setItem("sessionToken", data.sessionToken);
      localStorage.removeItem("tempUsername");
      
      // Fetch complete user data from backend
      await getCurrentUserData();
      
      logSecurityEvent('OTPSuccess', `OTP validated for ${sanitizeInput(user)}.`);
      window.location.href = "dashboard-simple.html";
    } else {
      document.getElementById("otpError").innerText = data.error || "Invalid OTP!";
      logSecurityEvent('OTPFailure', `Invalid OTP entered for ${sanitizeInput(user)}.`);
    }
  } catch (error) {
    console.error(error);
    document.getElementById("otpError").innerText = "Error verifying OTP. Check console.";
  }
}

// RESEND OTP - Actually resends OTP by calling login again
async function resendOTP() {
  const user = localStorage.getItem("tempUsername");
  if (!user) {
    alert("Session expired. Please login again.");
    window.location.href = "login.html";
    return;
  }

  // Get the password from the user (we don't store it for security)
  const pass = prompt("Please enter your password to resend OTP:");
  if (!pass) {
    return; // User cancelled
  }

  try {
    const response = await fetch(`${API_BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ user, pass })
    });
    const data = await response.json();

    if (response.ok) {
      // Reset OTP expiration time
      localStorage.setItem("otpExpireTS", (Date.now() + 30 * 1000).toString());
      alert("OTP resent! Check your email.");
      // Restart the timer
      startOTP();
    } else {
      alert(data.error || "Failed to resend OTP");
      if (data.error === "Invalid credentials") {
        // Wrong password, redirect to login
        localStorage.removeItem("tempUsername");
        window.location.href = "login.html";
      }
    }
  } catch (error) {
    console.error(error);
    alert("Error resending OTP. Check console.");
  }
}

// Fetch current user data from backend (keeps data in sync)
async function getCurrentUserData() {
  const sessionToken = localStorage.getItem("sessionToken");
  if (!sessionToken) {
    console.log("No session token found");
    return null;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/get-user`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionToken })
    });
    const data = await response.json();

    if (response.ok) {
      // Store user data fetched from backend (auto-synced, can't be modified by user)
      localStorage.setItem("currentUser", data.user);
      localStorage.setItem("email", data.email);
      localStorage.setItem("role", data.role);
      localStorage.setItem("lastLogin", new Date().toLocaleString());
      updateSessionExpiry();
      return data;
    } else {
      console.error("Failed to get user data:", data.error);
      return null;
    }
  } catch (error) {
    console.error("Error fetching user data:", error);
    return null;
  }
}

// Set username from query (for Google OAuth flow)
function applyUserFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const user = params.get('user');
  if (user) {
    localStorage.setItem('tempUsername', user);
  }
}

// PAGE LOAD
window.onload = async function () {
  console.log('Window onload started');
  applyTheme();
  registerActivityListeners();
  checkSessionValidity();
  applyUserFromQuery();
  
  // Check for valid session token
  const sessionToken = localStorage.getItem("sessionToken");
  const tempUsername = localStorage.getItem("tempUsername");
  
  // Protect dashboard page (requires session token)
  if (location.pathname.endsWith("dashboard.html")) {
    console.log('Dashboard page detected, session token:', !!sessionToken);
    if (!sessionToken) {
      console.log('No session token, redirecting to login');
      window.location.href = "login.html";
      return;
    }
    // Fetch latest user data from backend
    await getCurrentUserData();
  }
  
  // Protect OTP page (requires tempUsername from login)
  if (location.pathname.endsWith("otp.html")) {
    if (!tempUsername) {
      window.location.href = "login.html";
      return;
    }
  }
  
  let current = localStorage.getItem("currentUser");
  let role = localStorage.getItem("role");

  if (document.getElementById("welcomeUser")) {
    document.getElementById("welcomeUser").innerText = "Welcome " + current;
    document.getElementById("role").innerText = "Role: " + role;

    if (role === "admin") {
      document.getElementById("adminPanel").style.display = "block";
    }
  }

  if (document.getElementById("timer")) {
    startOTP();
  }

  if (document.getElementById("lastLogin")) {
    let lastLogin = localStorage.getItem("lastLogin") || "--";
    document.getElementById("lastLogin").innerText = "Last login: " + lastLogin;
  }

  if (document.getElementById("passStrength")) {
    let pass = getCurrentPassword();
    let strength = "Weak";
    if (pass.length >= 10 && /[A-Z]/.test(pass) && /[0-9]/.test(pass) && /[^A-Za-z0-9]/.test(pass)) strength = "Strong";
    else if (pass.length >= 8) strength = "Medium";
    document.getElementById("passStrength").innerText = strength;
  }

  if (document.getElementById("profilePanel")) {
    let email = "--";
    let current = localStorage.getItem("currentUser");
    let user = loadUsers().find(u => u.user === current);
    if (user) {
      email = user.email;
      document.getElementById("profileName").innerText = "Name: " + current;
      document.getElementById("profileEmail").innerText = "Email: " + email;
      document.getElementById("profileRole").innerText = "Role: " + role;
    }
  }

  if (document.getElementById("score")) {
    let score = calculateSecurityScore();
    let scoreEl = document.getElementById("score");
    scoreEl.innerText = score + "%";
    scoreEl.className = "security-badge " + (score >= 80 ? "security-good" : (score >= 50 ? "security-warn" : "security-bad"));
  }

  if (document.getElementById("mfaStatus")) {
    let mfaEnabled = localStorage.getItem("mfaEnabled") === "true";
    let mfaEl = document.getElementById("mfaStatus");
    mfaEl.innerText = mfaEnabled ? "Enabled" : "Disabled";
    mfaEl.className = "security-badge " + (mfaEnabled ? "security-good" : "security-warn");
  }

  if (document.getElementById("accountStatus")) {
    let blocked = localStorage.getItem("blockedUsers") ? localStorage.getItem("blockedUsers").split(",") : [];
    let status = blocked.includes(current) ? "Blocked" : "Active";
    let acctEl = document.getElementById("accountStatus");
    acctEl.innerText = status;
    acctEl.className = "security-badge " + (status === "Active" ? "security-good" : "security-bad");
  }

  renderNotificationHistory();
  renderSecurityLog();
  renderLoginActivityTable();
  setupChartJS();

  // Initialize new dashboard features
  if (location.pathname.endsWith("dashboard.html")) {
    console.log('Starting dashboard initialization...');
    
    // Set a safety timeout to hide loader after 10 seconds regardless
    const safetyTimeout = setTimeout(() => {
      console.log('Safety timeout triggered - hiding loader');
      const loader = document.getElementById("pageLoader");
      if (loader) {
        loader.style.display = "none";
      }
    }, 10000);
    
    // Load dashboard features with error handling
    Promise.allSettled([
      loadAuthOverview().catch(err => console.error('Auth overview error:', err)),
      loadUsers().catch(err => console.error('Users error:', err))
    ]).then((results) => {
      console.log('Dashboard async initialization results:', results);
      clearTimeout(safetyTimeout); // Clear safety timeout since we completed
      
      // Load synchronous functions after async ones complete
      loadSecurityAlerts();
      loadMFAStatus();
      loadVulnerabilityStatus();
      
      // Hide page loader after initialization
      const loader = document.getElementById("pageLoader");
      if (loader) {
        console.log('Hiding page loader...');
        loader.style.opacity = "0";
        setTimeout(() => {
          loader.style.display = "none";
          console.log('Page loader hidden');
          // Add staggered animations to sections
          const sections = document.querySelectorAll('.section');
          sections.forEach((section, index) => {
            section.style.animationDelay = `${index * 0.1}s`;
          });

          // Draw the login activity chart after sections appear
          drawLoginChart();
          startRealTimeGraphUpdates();
        }, 500);
      } else {
        console.error('Page loader element not found!');
      }
      
      console.log('Dashboard initialization complete');
    }).catch(err => {
      console.error('Dashboard initialization failed:', err);
      clearTimeout(safetyTimeout);
      // Still hide loader even if initialization fails
      const loader = document.getElementById("pageLoader");
      if (loader) {
        loader.style.display = "none";
      }
    });
  }
};

function setupChartJS() {
  const canvas = document.getElementById('loginChart');
  if (!canvas) return;

  if (typeof Chart === 'undefined') {
    console.warn('Chart.js not loaded; using fallback charting.');
    return;
  }

  if (loginChartInstance) {
    loginChartInstance.destroy();
  }

  const ctx = canvas.getContext('2d');

  loginChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: loginChartLabels,
      datasets: [{
        label: 'Login Activity',
        data: loginChartData,
        backgroundColor: loginChartData.map(value => value > 7 ? 'rgba(239, 68, 68, 0.6)' : 'rgba(56, 189, 248, 0.6)'),
        borderColor: loginChartData.map(value => value > 7 ? 'rgba(220, 38, 38, 1)' : 'rgba(14, 165, 233, 1)'),
        borderWidth: 2,
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(148, 163, 184, 0.2)' },
          ticks: { color: '#e2e8f0', stepSize: 1 }
        },
        x: {
          grid: { display: false },
          ticks: { color: '#e2e8f0' }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: { enabled: true }
      },
      animation: { duration: 700 }
    }
  });
}

function drawLoginChart() {
  if (loginChartInstance && typeof loginChartInstance.update === 'function') {
    loginChartInstance.data.labels = loginChartLabels;
    loginChartInstance.data.datasets[0].data = loginChartData;
    loginChartInstance.data.datasets[0].backgroundColor = loginChartData.map(value => value > 7 ? 'rgba(239, 68, 68, 0.6)' : 'rgba(56, 189, 248, 0.6)');
    loginChartInstance.data.datasets[0].borderColor = loginChartData.map(value => value > 7 ? 'rgba(220, 38, 38, 1)' : 'rgba(14, 165, 233, 1)');
    loginChartInstance.update();
  } else {
    setupChartJS();
  }

  if (loginChartData.some(value => value > 7)) {
    notify('High login traffic in recent activity, check for potential brute-force attacks.', 'warning');
  }
}

function notify(message, type = 'success') {
  const wrap = document.getElementById('notificationWrap');
  if (!wrap) return;

  const note = document.createElement('div');
  note.className = `notification ${type}`;
  note.innerText = message;

  wrap.appendChild(note);
  addPersistentNotification(message, type);
  logSecurityEvent('Notification', `${type}: ${message}`);

  setTimeout(() => {
    note.style.opacity = '0';
    note.style.transform = 'translateX(15px)';
    setTimeout(() => note.remove(), 400);
  }, 3200);
}

function startRealTimeGraphUpdates() {
  if (chartUpdateInterval) clearInterval(chartUpdateInterval);
  chartUpdateInterval = setInterval(() => {
    if (!checkSessionValidity()) return;

    const newValue = Math.max(0, Math.min(12, Math.round(1 + Math.random() * 10)));
    loginChartData.shift();
    loginChartData.push(newValue);

    const now = new Date();
    loginChartLabels.shift();
    loginChartLabels.push(`${now.getHours()}:${String(now.getMinutes()).padStart(2, '0')}`);

    drawLoginChart();

    if (newValue > 9) {
      logSecurityEvent('HighTraffic', `Login spike detected (${newValue} attempts).`);
      notify(`High login traffic now (${newValue} attempts)`, 'warning');
    } else {
      logSecurityEvent('TrafficUpdate', `Login count updated to ${newValue}.`);
      notify(`Login update: ${newValue} attempts`, 'success');
    }
  }, 3000);
}

function applyTheme() {
  const theme = localStorage.getItem('dashboardTheme') || 'dark';
  document.documentElement.setAttribute('data-theme', theme);

  if (theme === 'dark') {
    document.body.style.background = 'radial-gradient(circle at 20% 20%, #1f2937 0%, #020617 35%, #020617 100%)';
  } else {
    document.body.style.background = 'radial-gradient(circle at 20% 20%, #f8fafc 0%, #e5e7eb 40%, #e5e7eb 100%)';
  }
}

function toggleTheme() {
  const current = localStorage.getItem('dashboardTheme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem('dashboardTheme', next);
  applyTheme();
  notify(`${next} mode activated`, 'success');
}

function registerActivityListeners() {
  ['mousemove', 'keydown', 'click', 'scroll'].forEach(evt => {
    window.addEventListener(evt, updateSessionExpiry);
  });

  setInterval(() => {
    if (!checkSessionValidity()) {
      clearInterval(chartUpdateInterval);
    }
  }, 30000);
}

function toggleProfile() {
  let panel = document.getElementById("profilePanel");
  if (!panel) return;
  panel.style.display = panel.style.display === "none" ? "block" : "none";
  panel.classList.add("card-toggle");
}

function editProfile() {
  let newEmail = prompt("Update your email:");
  if (!newEmail) return;
  let current = localStorage.getItem("currentUser");
  let usersList = loadUsers();
  let found = usersList.find(u => u.user === current);
  if (found) {
    found.email = newEmail;
    saveUsers();
    document.getElementById("profileEmail").innerText = "Email: " + newEmail;
    alert("Profile updated.");
  }
}

function calculateSecurityScore() {
  let score = 60;
  let mfaEnabled = localStorage.getItem("mfaEnabled") === "true";
  if (mfaEnabled) score += 20;
  let pass = getCurrentPassword();
  if (pass && pass.length >= 12 && /[A-Z]/.test(pass) && /[a-z]/.test(pass) && /[0-9]/.test(pass) && /[^A-Za-z0-9]/.test(pass)) {
    score += 20;
  } else if (pass && pass.length >= 8) {
    score += 10;
  }
  return Math.min(99, score);
}

function getCurrentPassword() {
  let current = localStorage.getItem("currentUser");
  let allUsers = loadUsers();
  let found = allUsers.find(u => u.user === current);
  return found ? found.pass : "";
}

function sanitizeInput(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/[<>"'`;/\\]/g, '');
}

function getStoredNotifications() {
  return JSON.parse(localStorage.getItem(notificationStorageKey) || '[]');
}

function saveStoredNotifications(notifs) {
  localStorage.setItem(notificationStorageKey, JSON.stringify(notifs));
}

function addPersistentNotification(message, type = 'info') {
  const notifications = getStoredNotifications();
  const entry = { message, type, timestamp: new Date().toISOString() };
  notifications.unshift(entry);
  localStorage.setItem(notificationStorageKey, JSON.stringify(notifications.slice(0, 30)));
  renderNotificationHistory();
}

function renderNotificationHistory() {
  const historyEl = document.getElementById('notificationHistory');
  if (!historyEl) return;

  const list = getStoredNotifications();
  historyEl.innerHTML = '';
  if (!list.length) {
    historyEl.innerHTML = '<li>No notifications collected yet.</li>';
    return;
  }

  list.forEach(item => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${item.type.toUpperCase()}:</strong> ${item.message} <span style="opacity:.65;font-size:.75rem;">${new Date(item.timestamp).toLocaleString()}</span>`;
    historyEl.appendChild(li);
  });
}

function clearNotificationHistory() {
  localStorage.removeItem(notificationStorageKey);
  renderNotificationHistory();
}

function getSecurityLog() {
  return JSON.parse(localStorage.getItem(securityLogStorageKey) || '[]');
}

function saveSecurityLog(logs) {
  localStorage.setItem(securityLogStorageKey, JSON.stringify(logs));
}

function logSecurityEvent(eventType, details) {
  const logs = getSecurityLog();
  const entry = { eventType, details: sanitizeInput(details), timestamp: new Date().toISOString() };
  logs.unshift(entry);
  localStorage.setItem(securityLogStorageKey, JSON.stringify(logs.slice(0, 80)));
  renderSecurityLog();
  renderLoginActivityTable();
}

function renderSecurityLog() {
  const logEl = document.getElementById('securityLog');
  if (!logEl) return;

  const logs = getSecurityLog();
  if (!logs.length) {
    logEl.innerHTML = '<div class="security-entry">No security events captured yet.</div>';
    return;
  }

  logEl.innerHTML = '';
  logs.forEach(item => {
    const div = document.createElement('div');
    div.className = 'security-entry';
    div.innerHTML = `<strong>${item.eventType}</strong> - ${item.details} <span style="opacity:.65; font-size:.75rem; float:right;">${new Date(item.timestamp).toLocaleString()}</span>`;
    logEl.appendChild(div);
  });
}

function renderLoginActivityTable() {
  const tableBody = document.querySelector('.login-activity tbody');
  if (!tableBody) return;

  const events = getSecurityLog().filter(item => item.eventType.startsWith('Login')).slice(0, 5);
  if (!events.length) {
    tableBody.innerHTML = '<tr><td colspan="2">No activity yet</td></tr>';
    return;
  }

  tableBody.innerHTML = '';
  events.forEach(item => {
    const tr = document.createElement('tr');
    const date = new Date(item.timestamp).toLocaleString();
    let status = 'Info';
    if (item.eventType === 'LoginSuccess') status = 'Success';
    else if (item.eventType === 'LoginFailure') status = 'Failed';
    else if (item.eventType === 'LoginAttempt') status = 'Attempt';

    tr.innerHTML = `<td>${date}</td><td>${status} - ${item.details}</td>`;
    tableBody.appendChild(tr);
  });
}

function clearSecurityLog() {
  localStorage.removeItem(securityLogStorageKey);
  renderSecurityLog();
}

function updateSessionExpiry() {
  localStorage.setItem(sessionExpiryKey, (Date.now() + INACTIVITY_TIMEOUT_MS).toString());
}

function checkSessionValidity() {
  const expiry = parseInt(localStorage.getItem(sessionExpiryKey) || '0', 10);
  if (!expiry || Date.now() > expiry) {
    notify('Session expired due to inactivity, logging out.', 'warning');
    logout();
    return false;
  }
  updateSessionExpiry();
  return true;
}

function changePassword() {
  let oldPass = document.getElementById("oldPass").value;
  let newPass = document.getElementById("newPass").value;
  let msg = document.getElementById("passMsg");

  if (!oldPass || !newPass) {
    msg.innerText = "Please fill both password fields.";
    msg.className = "error";
    return;
  }

  let current = localStorage.getItem("currentUser");
  let usersList = loadUsers();
  let found = usersList.find(u => u.user === current);

  if (!found || found.pass !== oldPass) {
    msg.innerText = "Old password mismatch.";
    msg.className = "error";
    return;
  }

  if (newPass.length < 8) {
    msg.innerText = "New password should be at least 8 characters.";
    msg.className = "error";
    return;
  }

  found.pass = newPass;
  users = usersList;
  saveUsers();
  msg.innerText = "Password updated successfully!";
  msg.className = "success";
  localStorage.setItem("lastLogin", new Date().toLocaleString());
}

function toggleMFA() {
  let enabled = localStorage.getItem("mfaEnabled") === "true";
  localStorage.setItem("mfaEnabled", (!enabled).toString());
  let status = document.getElementById("mfaStatus");
  status.innerText = enabled ? "Disabled" : "Enabled";
  status.className = enabled ? "security-badge security-warn" : "security-badge security-good";
  notify(`MFA ${enabled ? 'disabled' : 'enabled'}`, 'success');
}

function blockUser() {
  const currentRole = localStorage.getItem('role');
  if (currentRole !== 'admin') {
    notify('Requires admin privileges to block users.', 'error');
    return;
  }

  let user = sanitizeInput(prompt("Enter username to block:"));
  if (!user) return;
  let blocked = localStorage.getItem("blockedUsers") ? localStorage.getItem("blockedUsers").split(",") : [];
  if (!blocked.includes(user)) blocked.push(user);
  localStorage.setItem("blockedUsers", blocked.join(","));
  logSecurityEvent('AdminAction', `User ${user} blocked by admin.`);
  notify(user + " is now blocked.", 'warning');
}

function unblockUser() {
  const currentRole = localStorage.getItem('role');
  if (currentRole !== 'admin') {
    notify('Requires admin privileges to unblock users.', 'error');
    return;
  }

  let user = sanitizeInput(prompt("Enter username to unblock:"));
  if (!user) return;
  let blocked = localStorage.getItem("blockedUsers") ? localStorage.getItem("blockedUsers").split(",") : [];
  blocked = blocked.filter(u => u !== user);
  localStorage.setItem("blockedUsers", blocked.join(","));
  logSecurityEvent('AdminAction', `User ${user} unblocked by admin.`);
  notify(user + " is now unblocked.", 'success');
}

// LOGOUT
function logout() {
  const usersBackup = localStorage.getItem('users');
  const notificationsBackup = localStorage.getItem(notificationStorageKey);
  const securityLogBackup = localStorage.getItem(securityLogStorageKey);

  localStorage.clear();

  if (usersBackup) localStorage.setItem('users', usersBackup);
  if (notificationsBackup) localStorage.setItem(notificationStorageKey, notificationsBackup);
  if (securityLogBackup) localStorage.setItem(securityLogStorageKey, securityLogBackup);

  window.location.href = "login.html";
}

// ===== ENHANCED ANIMATIONS AND INTERACTIONS =====

// Enhanced display functions with animations
function displayUsers(users) {
  const tbody = document.getElementById('userTableBody') || document.getElementById('usersBody') || document.getElementById('usersTableBody');
  if (!tbody) {
    console.warn('No user table element found on this page');
    return;
  }

  if (!Array.isArray(users)) {
    console.error('displayUsers: users parameter must be an array');
    return;
  }

  tbody.innerHTML = users.map((user, index) => `
    <tr style="--row-index: ${index};" class="fade-in">
      <td>${user.user || user.username || 'N/A'}</td>
      <td>${user.email || 'N/A'}</td>
      <td><span class="role-badge ${user.role || 'user'}">${user.role || 'user'}</span></td>
      <td><span class="status-badge ${user.status || 'active'}">${user.status || 'active'}</span></td>
      <td>
        <button onclick="editUser('${user.user || user.username || ''}')" class="small-btn">Edit</button>
        <button onclick="deleteUser('${user.user || user.username || ''}')" class="small-btn danger">Delete</button>
      </td>
    </tr>
  `).join('');
}

// Enhanced alert display with animations
function loadSecurityAlerts() {
  const alerts = JSON.parse(localStorage.getItem('securityAlerts') || '[]');
  const container = document.getElementById('alertsContainer');

  if (alerts.length === 0) {
    container.innerHTML = '<div class="alert alert-success fade-in">No security alerts at this time.</div>';
    return;
  }

  container.innerHTML = alerts.slice(0, 10).map((alert, index) => `
    <div class="alert-item ${alert.type || 'warning'} fade-in" style="animation-delay: ${index * 0.1}s;">
      ${alert.icon || '⚠️'} ${alert.message}
      <small style="float: right;">${new Date(alert.timestamp).toLocaleTimeString()}</small>
    </div>
  `).join('');
}

// Enhanced notification system with animations
function notify(message, type = 'info') {
  const wrap = document.getElementById('notificationWrap');
  if (!wrap) return;

  const notification = document.createElement('div');
  notification.className = `notification notification-${type} slide-down`;
  notification.innerHTML = `
    <span>${message}</span>
    <button onclick="this.parentElement.remove()" style="float: right; background: none; border: none; color: inherit; cursor: pointer;">×</button>
  `;

  wrap.appendChild(notification);

  // Auto remove after 5 seconds with fade out
  setTimeout(() => {
    notification.style.animation = 'fadeOut 0.5s ease forwards';
    setTimeout(() => notification.remove(), 500);
  }, 5000);
}

// Add loading states to buttons
function addLoadingState(button) {
  button.disabled = true;
  button.innerHTML = '<span class="loading-spinner"></span> Loading...';
  button.classList.add('loading');
}

function removeLoadingState(button, originalText) {
  button.disabled = false;
  button.innerHTML = originalText;
  button.classList.remove('loading');
}

// Enhanced button interactions
document.addEventListener('DOMContentLoaded', function() {
  // Add click animations to all buttons
  document.querySelectorAll('button').forEach(button => {
    button.addEventListener('click', function() {
      this.style.transform = 'scale(0.95)';
      setTimeout(() => {
        this.style.transform = '';
      }, 150);
    });
  });

  // Add hover animations to cards
  document.querySelectorAll('.card').forEach(card => {
    card.addEventListener('mouseenter', function() {
      this.style.transform = 'translateY(-5px) scale(1.02)';
    });

    card.addEventListener('mouseleave', function() {
      this.style.transform = '';
    });
  });
});

// Enhanced modal animations
function showAddUserModal() {
  const modal = document.getElementById('addUserModal');
  modal.style.display = 'flex';
  modal.classList.add('fade-in');

  // Focus first input with animation
  setTimeout(() => {
    const usernameInput = document.getElementById('newUserUsername');
    if (usernameInput) {
      usernameInput.focus();
      usernameInput.style.transform = 'scale(1.02)';
    }
  }, 300);
}

function closeModal() {
  const modal = document.getElementById('addUserModal');
  modal.style.animation = 'fadeOut 0.3s ease forwards';
  setTimeout(() => {
    modal.style.display = 'none';
    modal.style.animation = '';
  }, 300);
}

// Enhanced search with animations
function searchDashboard() {
  const query = document.getElementById('searchInput').value.toLowerCase();
  const sections = document.querySelectorAll('.section');

  sections.forEach(section => {
    const text = section.textContent.toLowerCase();
    const h3 = section.querySelector('h3');
    if (h3) {
      const title = h3.textContent.toLowerCase();
      if (text.includes(query) || title.includes(query) || query === '') {
        section.style.display = 'block';
        section.style.animation = 'fadeInScale 0.3s ease';
      } else {
        section.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => section.style.display = 'none', 300);
      }
    }
  });
}

// Enhanced theme toggle with smooth transitions
function toggleTheme() {
  const current = localStorage.getItem('dashboardTheme') || 'dark';
  const next = current === 'dark' ? 'light' : 'dark';
  localStorage.setItem('dashboardTheme', next);
  applyTheme();
  notify(`${next} mode activated`, 'success');

  // Animate theme toggle
  const themeBtn = document.querySelector('.theme-btn');
  if (themeBtn) {
    themeBtn.style.transform = 'rotate(360deg)';
    setTimeout(() => themeBtn.style.transform = '', 500);
  }

  // Add transition class to all elements
  document.body.classList.add('theme-transition');
  setTimeout(() => document.body.classList.remove('theme-transition'), 500);
}

// Enhanced panel toggles with animations
function toggleProfile() {
  const panel = document.getElementById('profilePanel');
  if (panel.style.display === 'none' || !panel.style.display) {
    panel.style.display = 'block';
    panel.classList.add('slide-down');
  } else {
    panel.classList.add('slide-up');
    setTimeout(() => panel.style.display = 'none', 500);
  }
}

function toggleSettings() {
  const panel = document.getElementById('settingsPanel');
  if (panel.style.display === 'none' || panel.style.display === '') {
    panel.style.display = 'block';
    panel.classList.add('slide-down');
    loadSettings();
  } else {
    panel.classList.add('slide-up');
    setTimeout(() => panel.style.display = 'none', 500);
  }
}

// Enhanced metric updates with animations
function updateMetric(elementId, newValue) {
  const element = document.getElementById(elementId);
  if (!element) return;

  element.style.transform = 'scale(1.2)';
  element.style.color = '#60a5fa';

  setTimeout(() => {
    element.textContent = newValue;
    element.style.transform = '';
    setTimeout(() => element.style.color = '', 500);
  }, 200);
}

// Enhanced security scan with animations
function runSecurityScan() {
  const scanBtn = document.querySelector('button[onclick="runSecurityScan()"]');
  if (scanBtn) {
    addLoadingState(scanBtn);

    notify('Running security scan...', 'info');

    // Simulate security scan with progress animation
    let progress = 0;
    const progressInterval = setInterval(() => {
      progress += 10;
      if (progress <= 100) {
        scanBtn.innerHTML = `<span class="loading-spinner"></span> Scanning... ${progress}%`;
      } else {
        clearInterval(progressInterval);
        removeLoadingState(scanBtn, 'Run Security Scan');

        const vulnerabilities = checkForVulnerabilities();
        if (vulnerabilities.length > 0) {
          addSecurityAlert('warning', `Security scan found ${vulnerabilities.length} potential issues`, '🔍');
          notify(`Security scan complete. Found ${vulnerabilities.length} issues.`, 'warning');
        } else {
          addSecurityAlert('success', 'Security scan completed - No vulnerabilities found', '✅');
          notify('Security scan complete - System secure!', 'success');
        }
      }
    }, 300);
  }
}

// Enhanced alert addition with animations
function addSecurityAlert(type, message, icon = '⚠️') {
  const alerts = JSON.parse(localStorage.getItem('securityAlerts') || '[]');
  alerts.unshift({
    type,
    message,
    icon,
    timestamp: Date.now()
  });

  // Keep only last 50 alerts
  if (alerts.length > 50) alerts.splice(50);

  localStorage.setItem('securityAlerts', JSON.stringify(alerts));
  loadSecurityAlerts();

  // Animate notification count
  const notifCount = document.getElementById('notifCount');
  if (notifCount) {
    notifCount.style.transform = 'scale(1.5)';
    notifCount.style.color = '#ef4444';
    setTimeout(() => {
      notifCount.style.transform = '';
      notifCount.style.color = '';
    }, 500);
  }
}

// Enhanced tab switching with animations
function showTab(tabName) {
  // Hide all tabs with fade out
  document.querySelectorAll('.tab-content').forEach(tab => {
    tab.style.animation = 'fadeOut 0.3s ease forwards';
    setTimeout(() => tab.style.display = 'none', 300);
  });

  // Update button states
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  event.target.classList.add('active');

  // Show selected tab with fade in
  setTimeout(() => {
    const tabElement = document.getElementById(tabName + 'Tab');
    if (tabElement) {
      tabElement.style.display = 'block';
      tabElement.style.animation = 'fadeIn 0.3s ease';
    }
  }, 300);
}

// Enhanced logout with animation
function logout() {
  // Add fade out animation
  document.body.style.animation = 'fadeOut 0.5s ease';

  setTimeout(() => {
    const usersBackup = localStorage.getItem('users');
    const notificationsBackup = localStorage.getItem(notificationStorageKey);
    const securityLogBackup = localStorage.getItem(securityLogStorageKey);

    localStorage.clear();

    if (usersBackup) localStorage.setItem('users', usersBackup);
    if (notificationsBackup) localStorage.setItem(notificationStorageKey, notificationsBackup);
    if (securityLogBackup) localStorage.setItem(securityLogStorageKey, securityLogBackup);

    window.location.href = "login.html";
  }, 500);
}

// Add loading spinner CSS class
const style = document.createElement('style');
style.textContent = `
  .loading-spinner {
    display: inline-block;
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-radius: 50%;
    border-top-color: #fff;
    animation: rotate 1s ease-in-out infinite;
    margin-right: 8px;
  }

  .notification {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 15px 20px;
    border-radius: 8px;
    color: white;
    z-index: 1000;
    animation: slideInRight 0.5s ease;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
  }

  .notification-success { background: #22c55e; }
  .notification-warning { background: #f59e0b; }
  .notification-error { background: #ef4444; }
  .notification-info { background: #3b82f6; }

  @keyframes fadeOut {
    from { opacity: 1; }
    to { opacity: 0; }
  }

  @keyframes rotate {
    to { transform: rotate(360deg); }
  }

  @keyframes slideInRight {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
`;
document.head.appendChild(style);