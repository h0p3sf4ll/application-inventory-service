const form = document.querySelector("#scanForm");
const startScanButton = document.querySelector("#startScan");
const stopScanButton = document.querySelector("#stopScan");
const refreshButton = document.querySelector("#refreshScans");
const resetButton = document.querySelector("#resetForm");
const toggleTokenButton = document.querySelector("#toggleToken");
const copyCommandButton = document.querySelector("#copyCommand");
const clearLogsButton = document.querySelector("#clearLogs");
const downloadLogsButton = document.querySelector("#downloadLogs");
const activeStatus = document.querySelector("#activeStatus");
const activeTitle = document.querySelector("#activeTitle");
const detectedCount = document.querySelector("#detectedCount");
const runtimeValue = document.querySelector("#runtimeValue");
const commandLine = document.querySelector("#commandLine");
const runList = document.querySelector("#runList");
const reportList = document.querySelector("#reportList");
const reportCount = document.querySelector("#reportCount");
const scanCount = document.querySelector("#scanCount");
const logsElement = document.querySelector("#logs");
const toast = document.querySelector("#toast");
const formStatus = document.querySelector("#formStatus");

const state = {
  scans: [],
  activeScan: null,
  eventSource: null,
  logs: [],
  timer: null,
};

const persistedFields = [
  "provider",
  "org",
  "project",
  "repo",
  "baseUrl",
  "outPrefix",
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
  "verbose",
];

document.addEventListener("DOMContentLoaded", async () => {
  loadForm();
  syncProviderFields();
  bindEvents();
  await loadScans();
  state.timer = window.setInterval(tick, 1000);
});

function bindEvents() {
  form.addEventListener("change", () => {
    syncProviderFields();
    saveForm();
  });
  form.addEventListener("input", saveForm);
  startScanButton.addEventListener("click", startScan);
  stopScanButton.addEventListener("click", stopScan);
  refreshButton.addEventListener("click", loadScans);
  resetButton.addEventListener("click", resetForm);
  toggleTokenButton.addEventListener("click", toggleToken);
  copyCommandButton.addEventListener("click", copyCommand);
  clearLogsButton.addEventListener("click", () => {
    state.logs = [];
    renderLogs();
  });
  downloadLogsButton.addEventListener("click", downloadLogs);
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
      headers: {"Content-Type": "application/json"},
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
    const response = await fetch(`/api/scans/${state.activeScan.id}/stop`, {method: "POST"});
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
    runtimeValue.textContent = "0s";
    commandLine.textContent = "appsec-scan-router";
    copyCommandButton.disabled = true;
    stopScanButton.disabled = true;
    downloadLogsButton.disabled = true;
    return;
  }
  activeStatus.textContent = capitalize(scan.status);
  activeStatus.className = `status-${scan.status}`;
  activeTitle.textContent = `${scan.org || "Unknown"} · ${scan.target || "all"} · ${providerLabel(scan.provider)}`;
  detectedCount.textContent = String(scan.detectedCount || 0);
  runtimeValue.textContent = scanRuntime(scan);
  commandLine.textContent = scan.command || "appsec-scan-router";
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
  const reports = state.activeScan ? state.activeScan.reports || [] : [];
  reportCount.textContent = String(reports.length);
  if (!reports.length) {
    reportList.innerHTML = '<div class="empty-state">No reports</div>';
    return;
  }
  reportList.innerHTML = reports.map((report) => `
    <a class="report-item" href="${escapeHtml(report.url)}">
      <strong>${escapeHtml(report.name)}</strong>
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
    outPrefix: value(data, "outPrefix") || "appsec_scan_router",
    minConfidence: value(data, "minConfidence") || "medium",
    activityMode: value(data, "activityMode") || "latest",
    branchAgeDays: numberValue(data, "branchAgeDays", 90),
    maxWorkers: numberValue(data, "maxWorkers", 8),
    branchWorkers: numberValue(data, "branchWorkers", 16),
    contentWorkers: numberValue(data, "contentWorkers", 16),
    maxCommitsPerRepo: numberValue(data, "maxCommitsPerRepo", 0),
    timeout: numberValue(data, "timeout", 30),
    storeLookup: data.has("storeLookup"),
    storeCountry: value(data, "storeCountry") || "US",
    storeTimeout: numberValue(data, "storeTimeout", 15),
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

function loadForm() {
  const saved = JSON.parse(localStorage.getItem("appsec-scan-router-ui") || "{}");
  for (const name of persistedFields) {
    if (!(name in saved)) {
      continue;
    }
    const element = form.elements[name];
    if (!element) {
      continue;
    }
    if (element instanceof RadioNodeList) {
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
    } else if (name === "storeLookup" || name === "verbose") {
      saved[name] = data.has(name);
    } else {
      saved[name] = value(data, name);
    }
  }
  localStorage.setItem("appsec-scan-router-ui", JSON.stringify(saved));
}

function resetForm() {
  form.reset();
  localStorage.removeItem("appsec-scan-router-ui");
  syncProviderFields();
  notify("Form reset.");
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

function providerLabel(provider) {
  return provider === "github-enterprise" ? "GitHub Enterprise" : "Azure DevOps";
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

function notify(message) {
  toast.textContent = message;
  toast.classList.add("visible");
  window.clearTimeout(notify.timeout);
  notify.timeout = window.setTimeout(() => toast.classList.remove("visible"), 2400);
}
