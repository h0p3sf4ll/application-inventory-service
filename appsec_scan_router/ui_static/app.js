const form = document.querySelector("#scanForm");
const startScanButton = document.querySelector("#startScan");
const stopScanButton = document.querySelector("#stopScan");
const refreshButton = document.querySelector("#refreshScans");
const resetDefaultsButton = document.querySelector("#resetDefaults");
const toggleTokenButton = document.querySelector("#toggleToken");
const loginGitHub = document.querySelector("#loginGitHub");
const logoutGitHub = document.querySelector("#logoutGitHub");
const forgetToken = document.querySelector("#forgetToken");
const authStatus = document.querySelector("#authStatus");
const saveTokenHint = document.querySelector("#saveTokenHint");
const copyCommandButton = document.querySelector("#copyCommand");
const clearLogsButton = document.querySelector("#clearLogs");
const downloadLogsButton = document.querySelector("#downloadLogs");
const activeStatus = document.querySelector("#activeStatus");
const activeTitle = document.querySelector("#activeTitle");
const detectedCount = document.querySelector("#detectedCount");
const progressValue = document.querySelector("#progressValue");
const progressFill = document.querySelector("#progressFill");
const progressDetail = document.querySelector("#progressDetail");
const etaValue = document.querySelector("#etaValue");
const runtimeValue = document.querySelector("#runtimeValue");
const commandLine = document.querySelector("#commandLine");
const runList = document.querySelector("#runList");
const reportList = document.querySelector("#reportList");
const reportCount = document.querySelector("#reportCount");
const scanCount = document.querySelector("#scanCount");
const logsElement = document.querySelector("#logs");
const toast = document.querySelector("#toast");
const formStatus = document.querySelector("#formStatus");
const tabButtons = document.querySelectorAll("[data-view]");

const state = {
  scans: [],
  activeScan: null,
  eventSource: null,
  logs: [],
  timer: null,
  session: null,
};

const defaultValues = {
  outPrefix: "appsec_inventory_service",
  applicationTypes: [],
  minConfidence: "medium",
  activityMode: "latest",
  branchAgeDays: "90",
  maxWorkers: "8",
  branchWorkers: "16",
  contentWorkers: "16",
  maxCommitsPerRepo: "0",
  timeout: "30",
  storeCountry: "US",
  storeTimeout: "15",
  storeLookup: false,
  saveToken: false,
  postgresEnabled: true,
  postgresHost: "host.docker.internal",
  postgresPort: "5432",
  postgresDatabase: "postgres",
  postgresUser: "postgres",
  postgresPassword: "",
  postgresTable: "appsec_inventory_assets",
  verbose: false,
};

const persistedFields = [
  "provider",
  "org",
  "project",
  "repo",
  "baseUrl",
  "applicationTypes",
  "minConfidence",
  "activityMode",
  "branchAgeDays",
  "maxWorkers",
  "branchWorkers",
  "contentWorkers",
  "maxCommitsPerRepo",
  "timeout",
  "storeLookup",
  "storeCountry",
  "storeTimeout",
  "postgresEnabled",
  "postgresHost",
  "postgresPort",
  "postgresDatabase",
  "postgresUser",
  "postgresTable",
  "verbose",
];

document.addEventListener("DOMContentLoaded", async () => {
  loadForm();
  syncProviderFields();
  syncDatabaseFields();
  syncMobileOptions();
  bindEvents();
  await loadSession();
  await loadScans();
  showAuthResult();
  state.timer = window.setInterval(tick, 1000);
});

function bindEvents() {
  form.addEventListener("change", () => {
    syncProviderFields();
    syncDatabaseFields();
    syncMobileOptions();
    syncCredentialFields();
    saveForm();
  });
  form.addEventListener("input", saveForm);
  startScanButton.addEventListener("click", startScan);
  stopScanButton.addEventListener("click", stopScan);
  refreshButton.addEventListener("click", loadScans);
  resetDefaultsButton.addEventListener("click", resetDefaults);
  toggleTokenButton.addEventListener("click", toggleToken);
  logoutGitHub.addEventListener("click", logout);
  forgetToken.addEventListener("click", forgetSavedToken);
  copyCommandButton.addEventListener("click", copyCommand);
  clearLogsButton.addEventListener("click", () => {
    state.logs = [];
    renderLogs();
  });
  downloadLogsButton.addEventListener("click", downloadLogs);
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => setActiveView(button.dataset.view));
  });
}

async function startScan() {
  if (!form.reportValidity()) {
    return;
  }
  const payload = formPayload();
  setBusy(true);
  try {
    const response = await fetch("/api/scans", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Scan could not be started.");
    }
    state.activeScan = data.scan;
    state.logs = data.scan.logsTail || [];
    await loadScans(data.scan.id);
    listenToScan(data.scan.id);
    await loadSession();
    notify("Scan started.");
  } catch (error) {
    notify(error.message || "Scan could not be started.");
  } finally {
    setBusy(false);
  }
}

async function stopScan() {
  if (!state.activeScan) {
    return;
  }
  try {
    const response = await fetch(`/api/scans/${state.activeScan.id}/stop`, {
      method: "POST",
      headers: authHeaders(false),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Stop failed.");
    }
    state.activeScan = data.scan;
    renderActiveScan();
    notify("Stop requested.");
  } catch (error) {
    notify(error.message || "Stop failed.");
  }
}

async function loadSession() {
  try {
    const response = await fetch("/api/session");
    const data = await response.json();
    state.session = data.session || null;
    renderAuth();
    syncCredentialFields();
  } catch (error) {
    state.session = null;
    renderAuth();
  }
}

async function logout() {
  try {
    const response = await fetch("/api/auth/logout", {
      method: "POST",
      headers: authHeaders(false),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Sign out failed.");
    }
    state.session = data.session || null;
    form.elements.saveToken.checked = false;
    renderAuth();
    syncCredentialFields();
    notify("Signed out.");
  } catch (error) {
    notify(error.message || "Sign out failed.");
  }
}

async function forgetSavedToken() {
  const provider = new FormData(form).get("provider") || "azure-devops";
  try {
    const response = await fetch("/api/credentials/delete", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({provider}),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Could not remove saved token.");
    }
    state.session = data.session || state.session;
    renderAuth();
    syncCredentialFields();
    notify("Saved token removed.");
  } catch (error) {
    notify(error.message || "Could not remove saved token.");
  }
}

async function loadScans(preferredId = "") {
  try {
    const response = await fetch("/api/scans");
    const data = await response.json();
    state.scans = data.scans || [];
    if (preferredId) {
      const selected = state.scans.find((scan) => scan.id === preferredId);
      if (selected) {
        selectScan(selected, false);
      }
    } else if (!state.activeScan && state.scans.length) {
      selectScan(state.scans[0], false);
    } else if (state.activeScan) {
      const refreshed = state.scans.find((scan) => scan.id === state.activeScan.id);
      if (refreshed) {
        state.activeScan = refreshed;
      }
    }
    renderAll();
  } catch (error) {
    notify(error.message || "Could not refresh scans.");
  }
}

async function selectScan(scan, connect = true) {
  try {
    const response = await fetch(`/api/scans/${scan.id}`);
    const data = await response.json();
    state.activeScan = data.scan || scan;
    state.logs = state.activeScan.logsTail || [];
    renderAll();
    if (connect && state.activeScan.status === "running") {
      listenToScan(state.activeScan.id);
    } else if (connect) {
      closeEventSource();
    }
  } catch (error) {
    notify(error.message || "Could not open scan.");
  }
}

function listenToScan(scanId) {
  closeEventSource();
  const source = new EventSource(`/api/scans/${scanId}/events`);
  state.eventSource = source;
  source.addEventListener("status", (event) => {
    state.activeScan = JSON.parse(event.data);
    mergeScan(state.activeScan);
    renderAll();
  });
  source.addEventListener("log", (event) => {
    const data = JSON.parse(event.data);
    if (data.line) {
      state.logs.push(data.line);
      if (state.logs.length > 1200) {
        state.logs = state.logs.slice(-1200);
      }
      renderLogs();
    }
  });
  source.addEventListener("done", async (event) => {
    state.activeScan = JSON.parse(event.data);
    mergeScan(state.activeScan);
    closeEventSource();
    await loadScans(state.activeScan.id);
    notify(`Scan ${state.activeScan.status}.`);
  });
}

function closeEventSource() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
}

function mergeScan(scan) {
  const index = state.scans.findIndex((candidate) => candidate.id === scan.id);
  if (index >= 0) {
    state.scans.splice(index, 1, scan);
  } else {
    state.scans.unshift(scan);
  }
}

function renderAll() {
  renderActiveScan();
  renderRuns();
  renderReports();
  renderLogs();
}

function renderActiveScan() {
  const scan = state.activeScan;
  if (!scan) {
    activeStatus.textContent = "Idle";
    activeStatus.className = "";
    activeTitle.textContent = "No scan selected";
    detectedCount.textContent = "0";
    progressValue.textContent = "0%";
    progressFill.style.width = "0%";
    progressDetail.textContent = "No scan running";
    etaValue.textContent = "Not started";
    runtimeValue.textContent = "0s";
    commandLine.textContent = "appsec-inventory-service";
    copyCommandButton.disabled = true;
    stopScanButton.disabled = true;
    downloadLogsButton.disabled = true;
    return;
  }
  activeStatus.textContent = capitalize(scan.status);
  activeStatus.className = `status-${scan.status}`;
  activeTitle.textContent = `${scan.org || "Unknown"} · ${scan.target || "all"} · ${providerLabel(scan.provider)} · ${applicationTypesLabel(scan.applicationTypes)}`;
  detectedCount.textContent = String(scan.detectedCount || 0);
  progressValue.textContent = scanProgress(scan);
  progressFill.style.width = `${scanPercent(scan)}%`;
  progressDetail.textContent = scanProgressDetail(scan);
  etaValue.textContent = scanEta(scan);
  runtimeValue.textContent = scanRuntime(scan);
  commandLine.textContent = scan.command || "appsec-inventory-service";
  copyCommandButton.disabled = !scan.command;
  stopScanButton.disabled = scan.status !== "running";
  downloadLogsButton.disabled = state.logs.length === 0;
}

function renderRuns() {
  scanCount.textContent = String(state.scans.length);
  if (!state.scans.length) {
    runList.innerHTML = '<div class="empty-state">No runs</div>';
    return;
  }
  runList.innerHTML = state.scans.map((scan) => {
    const active = state.activeScan && state.activeScan.id === scan.id ? " active" : "";
    return `
      <button class="run-item${active}" type="button" data-scan-id="${escapeHtml(scan.id)}">
        <span class="run-main">
          <strong>${escapeHtml(scan.org || "Unknown")} · ${escapeHtml(scan.target || "all")}</strong>
          <span class="status-chip status-${escapeHtml(scan.status)}">${escapeHtml(capitalize(scan.status))}</span>
        </span>
        <span class="run-meta">
          <span>${escapeHtml(providerLabel(scan.provider))}</span>
          <span>${escapeHtml(applicationTypesLabel(scan.applicationTypes))}</span>
          <span>${scan.postgresEnabled ? `PostgreSQL: ${escapeHtml(scan.postgresTable || "enabled")}` : "Files only"}</span>
          <span>${escapeHtml(formatDate(scan.startedAt))}</span>
        </span>
      </button>
    `;
  }).join("");
  runList.querySelectorAll("[data-scan-id]").forEach((button) => {
    button.addEventListener("click", () => {
      const selected = state.scans.find((scan) => scan.id === button.dataset.scanId);
      if (selected) {
        selectScan(selected);
      }
    });
  });
}

function renderReports() {
  const reports = state.scans.flatMap((scan) => (scan.reports || []).map((report) => ({...report, scan})));
  reportCount.textContent = String(reports.length);
  if (!reports.length) {
    reportList.innerHTML = '<div class="empty-state">No reports</div>';
    return;
  }
  reportList.innerHTML = reports.map((report) => `
    <a class="report-item" href="${escapeHtml(report.url)}">
      <span>
        <strong>${escapeHtml(report.name)}</strong>
        <small>${escapeHtml(report.scan.org || "Unknown")} · ${escapeHtml(report.scan.target || "all")}</small>
      </span>
      <span>${escapeHtml(formatBytes(report.size))}</span>
    </a>
  `).join("");
}

function renderLogs() {
  logsElement.textContent = state.logs.join("\n");
  logsElement.scrollTop = logsElement.scrollHeight;
  downloadLogsButton.disabled = state.logs.length === 0;
}

function formPayload() {
  const data = new FormData(form);
  const provider = data.get("provider") || "azure-devops";
  return {
    provider,
    org: value(data, "org"),
    project: provider === "azure-devops" ? value(data, "project") : "",
    repo: provider === "github-enterprise" ? value(data, "repo") : "",
    baseUrl: provider === "github-enterprise" ? value(data, "baseUrl") : "",
    token: value(data, "token"),
    outPrefix: defaultValues.outPrefix,
    applicationTypes: checkedValues("applicationTypes"),
    minConfidence: value(data, "minConfidence") || defaultValues.minConfidence,
    activityMode: value(data, "activityMode") || defaultValues.activityMode,
    branchAgeDays: numberValue(data, "branchAgeDays", Number(defaultValues.branchAgeDays)),
    maxWorkers: numberValue(data, "maxWorkers", Number(defaultValues.maxWorkers)),
    branchWorkers: numberValue(data, "branchWorkers", Number(defaultValues.branchWorkers)),
    contentWorkers: numberValue(data, "contentWorkers", Number(defaultValues.contentWorkers)),
    maxCommitsPerRepo: numberValue(data, "maxCommitsPerRepo", Number(defaultValues.maxCommitsPerRepo)),
    timeout: numberValue(data, "timeout", Number(defaultValues.timeout)),
    storeLookup: data.has("storeLookup"),
    saveToken: data.has("saveToken"),
    storeCountry: value(data, "storeCountry") || defaultValues.storeCountry,
    storeTimeout: numberValue(data, "storeTimeout", Number(defaultValues.storeTimeout)),
    postgresEnabled: data.has("postgresEnabled"),
    postgresHost: value(data, "postgresHost") || defaultValues.postgresHost,
    postgresPort: numberValue(data, "postgresPort", Number(defaultValues.postgresPort)),
    postgresDatabase: value(data, "postgresDatabase") || defaultValues.postgresDatabase,
    postgresUser: value(data, "postgresUser") || defaultValues.postgresUser,
    postgresPassword: value(data, "postgresPassword"),
    postgresTable: value(data, "postgresTable") || defaultValues.postgresTable,
    verbose: data.has("verbose"),
  };
}

function syncProviderFields() {
  const provider = new FormData(form).get("provider") || "azure-devops";
  document.querySelectorAll(".provider-azure").forEach((node) => {
    node.classList.toggle("hidden", provider !== "azure-devops");
  });
  document.querySelectorAll(".provider-github").forEach((node) => {
    node.classList.toggle("hidden", provider !== "github-enterprise");
  });
  form.querySelector('[name="baseUrl"]').required = provider === "github-enterprise";
  form.querySelector('[name="project"]').required = false;
  form.querySelector('[name="repo"]').required = false;
}

function syncDatabaseFields() {
  const enabled = form.querySelector('[name="postgresEnabled"]').checked;
  document.querySelectorAll(".database-fields").forEach((node) => {
    node.classList.toggle("hidden", !enabled);
  });
  for (const name of ["postgresHost", "postgresPort", "postgresDatabase", "postgresUser", "postgresTable"]) {
    form.elements[name].required = enabled;
  }
}

function syncMobileOptions() {
  const selected = checkedValues("applicationTypes");
  const mobileApplies = selected.length === 0 || selected.includes("mobile_app");
  document.querySelectorAll(".mobile-option").forEach((node) => {
    node.classList.toggle("hidden", !mobileApplies);
    node.querySelectorAll("input, select, button").forEach((control) => {
      control.disabled = !mobileApplies;
    });
  });
  if (!mobileApplies) {
    form.elements.storeLookup.checked = false;
  }
}

function syncCredentialFields() {
  const session = state.session || {};
  const provider = new FormData(form).get("provider") || "azure-devops";
  const loggedIn = Boolean(session.loggedIn);
  const hasSavedToken = Boolean((session.credentials || {})[provider]);
  form.elements.saveToken.disabled = !loggedIn;
  if (!loggedIn) {
    form.elements.saveToken.checked = false;
  }
  form.elements.token.placeholder = hasSavedToken ? "Uses saved token if blank" : "Uses environment token if blank";
  saveTokenHint.textContent = loggedIn
    ? hasSavedToken
      ? "Saved token available for this provider"
      : "Checked tokens are encrypted and saved for your GitHub user"
    : "Sign in with GitHub to save or reuse provider tokens";
  forgetToken.classList.toggle("hidden", !loggedIn || !hasSavedToken);
}

function loadForm() {
  const saved = JSON.parse(localStorage.getItem("appsec-inventory-service-ui") || "{}");
  applyDefaultValues();
  for (const name of persistedFields) {
    if (!(name in saved)) {
      continue;
    }
    const element = form.elements[name];
    if (!element) {
      continue;
    }
    if (Array.isArray(saved[name])) {
      setCheckboxGroup(name, saved[name]);
    } else if (element instanceof RadioNodeList) {
      element.value = saved[name];
    } else if (element.type === "checkbox") {
      element.checked = Boolean(saved[name]);
    } else {
      element.value = saved[name];
    }
  }
}

function saveForm() {
  const data = new FormData(form);
  const saved = {};
  for (const name of persistedFields) {
    if (name === "provider") {
      saved[name] = data.get(name);
    } else if (name === "applicationTypes") {
      saved[name] = checkedValues(name);
    } else if (name === "storeLookup" || name === "postgresEnabled" || name === "verbose") {
      saved[name] = data.has(name);
    } else {
      saved[name] = value(data, name);
    }
  }
  localStorage.setItem("appsec-inventory-service-ui", JSON.stringify(saved));
}

function resetDefaults() {
  applyDefaultValues();
  syncProviderFields();
  syncDatabaseFields();
  syncMobileOptions();
  syncCredentialFields();
  saveForm();
  notify("Scan defaults restored.");
}

function applyDefaultValues() {
  for (const [name, defaultValue] of Object.entries(defaultValues)) {
    const element = form.elements[name];
    if (!element) {
      continue;
    }
    if (element.type === "checkbox") {
      element.checked = Boolean(defaultValue);
    } else if (Array.isArray(defaultValue)) {
      setCheckboxGroup(name, defaultValue);
    } else {
      element.value = defaultValue;
    }
  }
}

function toggleToken() {
  const token = form.querySelector('[name="token"]');
  const showing = token.type === "text";
  token.type = showing ? "password" : "text";
  toggleTokenButton.textContent = showing ? "Show" : "Hide";
}

async function copyCommand() {
  if (!state.activeScan || !state.activeScan.command) {
    return;
  }
  await navigator.clipboard.writeText(state.activeScan.command);
  notify("Command copied.");
}

function downloadLogs() {
  if (!state.logs.length) {
    return;
  }
  const blob = new Blob([state.logs.join("\n")], {type: "text/plain"});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `${state.activeScan ? state.activeScan.id : "scan"}-logs.txt`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function setBusy(isBusy) {
  startScanButton.disabled = isBusy;
  formStatus.textContent = isBusy ? "Starting" : "Ready";
  formStatus.className = `status-chip ${isBusy ? "status-running" : "idle"}`;
}

function renderAuth() {
  const session = state.session || {};
  const loggedIn = Boolean(session.loggedIn);
  const enabled = Boolean(session.githubLoginEnabled);
  authStatus.textContent = loggedIn
    ? `Signed in as ${session.user && session.user.login ? session.user.login : "GitHub user"}`
    : enabled
      ? "Not signed in"
      : "GitHub login not configured";
  loginGitHub.classList.toggle("hidden", loggedIn || !enabled);
  logoutGitHub.classList.toggle("hidden", !loggedIn);
}

function authHeaders(jsonBody) {
  const headers = {};
  if (jsonBody) {
    headers["Content-Type"] = "application/json";
  }
  if (state.session && state.session.csrfToken) {
    headers["X-CSRF-Token"] = state.session.csrfToken;
  }
  return headers;
}

function showAuthResult() {
  const params = new URLSearchParams(window.location.search);
  const auth = params.get("auth");
  if (auth === "success") {
    notify("Signed in with GitHub.");
  } else if (auth === "failed") {
    notify("GitHub sign-in failed.");
  }
  if (auth) {
    window.history.replaceState({}, "", window.location.pathname);
  }
}

function tick() {
  if (state.activeScan) {
    runtimeValue.textContent = scanRuntime(state.activeScan);
  }
  const running = state.scans.some((scan) => scan.status === "running");
  if (running) {
    loadScans();
  }
}

function scanRuntime(scan) {
  if (!scan.startedAt) {
    return "0s";
  }
  const start = Date.parse(scan.startedAt);
  const end = scan.endedAt ? Date.parse(scan.endedAt) : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    return "0s";
  }
  const total = Math.max(0, Math.floor((end - start) / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return minutes ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function scanProgress(scan) {
  return `${scanPercent(scan)}%`;
}

function scanPercent(scan) {
  const progress = scan.progress || {};
  if (scan.status === "succeeded") {
    return 100;
  }
  const percent = Number(progress.percent || 0);
  if (!Number.isFinite(percent) || percent <= 0) {
    return 0;
  }
  return Math.max(0, Math.min(100, Math.round(percent)));
}

function scanProgressDetail(scan) {
  const progress = scan.progress || {};
  if (scan.status === "succeeded") {
    return "Scan complete";
  }
  if (scan.status === "failed") {
    return "Scan failed";
  }
  if (scan.status === "stopped") {
    return "Scan stopped";
  }
  const repoDone = Number(progress.repositoriesPrepared || 0);
  const repoTotal = Number(progress.repositoriesTotal || 0);
  const branchDone = Number(progress.branchesScanned || 0);
  const branchTotal = Number(progress.branchesTotal || 0);
  const repoText = repoTotal ? `${repoDone}/${repoTotal} repositories prepared` : "Preparing repositories";
  const branchText = branchTotal ? `${branchDone}/${branchTotal} branches scanned` : "Branches pending";
  return `${repoText} · ${branchText}`;
}

function scanEta(scan) {
  if (scan.status === "succeeded") {
    return "Done";
  }
  if (scan.status === "failed") {
    return "Stopped";
  }
  if (scan.status === "stopped") {
    return "Stopped";
  }
  if (scan.status !== "running") {
    return "Not started";
  }
  const seconds = Number((scan.progress || {}).etaSeconds);
  if (!Number.isFinite(seconds) || seconds <= 0) {
    return "Estimating";
  }
  return `About ${durationText(seconds)}`;
}

function durationText(totalSeconds) {
  const total = Math.max(1, Math.round(totalSeconds));
  if (total < 60) {
    return `${total}s`;
  }
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  if (minutes < 60) {
    return seconds ? `${minutes}m ${seconds}s` : `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  const remainingMinutes = minutes % 60;
  return remainingMinutes ? `${hours}h ${remainingMinutes}m` : `${hours}h`;
}

function providerLabel(provider) {
  return provider === "github-enterprise" ? "GitHub Enterprise" : "Azure DevOps";
}

function applicationTypesLabel(applicationTypes) {
  const values = Array.isArray(applicationTypes) ? applicationTypes : [];
  if (!values.length) {
    return "All types";
  }
  return values.map((type) => applicationTypeLabel(type)).join(", ");
}

function applicationTypeLabel(type) {
  const labels = {
    mobile_app: "Mobile app",
    web_app: "Web app",
    api_service: "API service",
    microservice: "Microservice",
    middleware: "Middleware",
    serverless: "Serverless",
    library: "Library",
    infrastructure: "Infrastructure",
    ai_enabled: "AI-enabled",
  };
  return labels[type] || String(type || "").replaceAll("_", " ");
}

function checkedValues(name) {
  return Array.from(form.querySelectorAll(`[name="${name}"]:checked`)).map((node) => node.value);
}

function setCheckboxGroup(name, values) {
  const selected = new Set(Array.isArray(values) ? values : []);
  form.querySelectorAll(`[name="${name}"]`).forEach((node) => {
    node.checked = selected.has(node.value);
  });
}

function value(data, name) {
  return String(data.get(name) || "").trim();
}

function numberValue(data, name, fallback) {
  const number = Number(value(data, name));
  return Number.isFinite(number) ? number : fallback;
}

function capitalize(text) {
  const value = String(text || "");
  return value ? value.charAt(0).toUpperCase() + value.slice(1) : "";
}

function formatDate(value) {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "" : date.toLocaleString();
}

function formatBytes(value) {
  const size = Number(value || 0);
  if (size < 1024) {
    return `${size} B`;
  }
  if (size < 1024 * 1024) {
    return `${(size / 1024).toFixed(1)} KB`;
  }
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function setActiveView(viewId) {
  document.querySelectorAll(".tab-view").forEach((view) => {
    const active = view.id === viewId;
    view.hidden = !active;
    view.classList.toggle("hidden", !active);
    view.classList.toggle("active", active);
  });
  tabButtons.forEach((button) => {
    const active = button.dataset.view === viewId;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
}

function notify(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(notify.timeout);
  notify.timeout = window.setTimeout(() => toast.classList.remove("visible"), 2400);
}
