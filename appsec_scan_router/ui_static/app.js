const form = document.querySelector("#scanForm");
const loginPage = document.querySelector("#loginPage");
const appShell = document.querySelector("#appShell");
const startScanButton = document.querySelector("#startScan");
const stopScanButton = document.querySelector("#stopScan");
const refreshButton = document.querySelector("#refreshScans");
const resetDefaultsButton = document.querySelector("#resetDefaults");
const toggleTokenButton = document.querySelector("#toggleToken");
const loginGitHub = document.querySelector("#loginGitHub");
const loginGitHubSso = document.querySelector("#loginGitHubSso");
const loginGoogleSso = document.querySelector("#loginGoogleSso");
const loginTestSso = document.querySelector("#loginTestSso");
const logoutGitHub = document.querySelector("#logoutGitHub");
const forgetToken = document.querySelector("#forgetToken");
const authStatus = document.querySelector("#authStatus");
const loginSummary = document.querySelector("#loginSummary");
const orgRequirementBadge = document.querySelector("#orgRequirementBadge");
const addAdoOrgPatButton = document.querySelector("#addAdoOrgPat");
const adoOrgPatList = document.querySelector("#adoOrgPatList");
const loadTargetsButton = document.querySelector("#loadTargets");
const selectAllTargetsButton = document.querySelector("#selectAllTargets");
const clearTargetFiltersButton = document.querySelector("#clearTargetFilters");
const targetFilterList = document.querySelector("#targetFilterList");
const targetFilterTitle = document.querySelector("#targetFilterTitle");
const targetFilterDefault = document.querySelector("#targetFilterDefault");
const targetFilterSummary = document.querySelector("#targetFilterSummary");
const targetSearch = document.querySelector("#targetSearch");
const githubSsoStatus = document.querySelector("#githubSsoStatus");
const googleSsoStatus = document.querySelector("#googleSsoStatus");
const testSsoStatus = document.querySelector("#testSsoStatus");
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
const checkDatabaseButton = document.querySelector("#checkDatabase");
const exportDatabaseCsvButton = document.querySelector("#exportDatabaseCsv");
const exportDatabaseJsonButton = document.querySelector("#exportDatabaseJson");
const databaseStatus = document.querySelector("#databaseStatus");
const tabButtons = document.querySelectorAll("[data-view]");

const state = {
  scans: [],
  activeScan: null,
  eventSource: null,
  logs: [],
  timer: null,
  session: null,
  database: null,
  adoOrgPats: [],
  sourceTargets: [],
  selectedTargets: [],
  sourceTargetErrors: [],
};

const defaultValues = {
  outPrefix: "application_inventory_service",
  applicationTypes: [],
  minConfidence: "medium",
  activityMode: "contributors",
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
  postgresHost: "localhost",
  postgresPort: "5432",
  postgresDatabase: "postgres",
  postgresUser: "postgres",
  postgresPassword: "",
  postgresSchema: "application_inventory",
  postgresTable: "application_inventory_assets",
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
  "postgresSchema",
  "postgresTable",
  "verbose",
];

document.addEventListener("DOMContentLoaded", async () => {
  loadForm();
  syncProviderFields();
  syncDatabaseFields();
  syncMobileOptions();
  syncAdoOrgPatInput();
  syncTargetFilterInput();
  bindEvents();
  renderShell();
  await loadSession();
  showAuthResult();
  if (isLoggedIn()) {
    await loadScans();
  } else {
    renderAll();
  }
  state.timer = window.setInterval(tick, 1000);
});

function bindEvents() {
  form.addEventListener("change", (event) => {
    if (sourceFieldChanged(event.target)) {
      clearDiscoveredTargets({silent: true});
    }
    syncProviderFields();
    syncDatabaseFields();
    syncMobileOptions();
    syncCredentialFields();
    saveForm();
  });
  form.addEventListener("input", saveForm);
  form.addEventListener("input", syncCredentialFields);
  startScanButton.addEventListener("click", startScan);
  stopScanButton.addEventListener("click", stopScan);
  refreshButton.addEventListener("click", loadScans);
  resetDefaultsButton.addEventListener("click", resetDefaults);
  toggleTokenButton.addEventListener("click", toggleToken);
  addAdoOrgPatButton.addEventListener("click", addAdoOrgPat);
  loadTargetsButton.addEventListener("click", loadSourceTargets);
  selectAllTargetsButton.addEventListener("click", selectVisibleTargets);
  clearTargetFiltersButton.addEventListener("click", () => clearSelectedTargets());
  targetSearch.addEventListener("input", renderTargetFilters);
  form.elements.adoOrgName.addEventListener("keydown", handleAdoOrgPatKeydown);
  form.elements.adoOrgPat.addEventListener("keydown", handleAdoOrgPatKeydown);
  logoutGitHub.addEventListener("click", logout);
  forgetToken.addEventListener("click", forgetSavedToken);
  loginGitHubSso.addEventListener("click", handleSsoClick);
  loginGoogleSso.addEventListener("click", handleSsoClick);
  loginTestSso.addEventListener("click", handleSsoClick);
  copyCommandButton.addEventListener("click", copyCommand);
  clearLogsButton.addEventListener("click", () => {
    state.logs = [];
    renderLogs();
  });
  downloadLogsButton.addEventListener("click", downloadLogs);
  checkDatabaseButton.addEventListener("click", checkDatabase);
  exportDatabaseCsvButton.addEventListener("click", () => exportDatabase("csv"));
  exportDatabaseJsonButton.addEventListener("click", () => exportDatabase("json"));
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => setActiveView(button.dataset.view));
  });
}

async function startScan() {
  if (!commitPendingAdoOrgPat({silent: true})) {
    return;
  }
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
    setActiveView("runsView");
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
    state.scans = [];
    state.activeScan = null;
    state.logs = [];
    state.adoOrgPats = [];
    clearDiscoveredTargets({silent: true});
    syncAdoOrgPatInput();
    form.elements.saveToken.checked = false;
    renderAuth();
    renderAll();
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
  if (!isLoggedIn()) {
    state.scans = [];
    state.activeScan = null;
    state.logs = [];
    renderAll();
    return;
  }
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
  renderDatabaseStatus();
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
    commandLine.textContent = "application-inventory-service";
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
  commandLine.textContent = scan.command || "application-inventory-service";
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

function renderDatabaseStatus() {
  const database = state.database;
  if (!database) {
    databaseStatus.className = "database-status";
    databaseStatus.innerHTML = `
      <strong>Not checked</strong>
      <span>Schema: ${escapeHtml(form.elements.postgresSchema.value || defaultValues.postgresSchema)}</span>
    `;
    return;
  }
  const connected = Boolean(database.connected);
  databaseStatus.className = `database-status ${connected ? "connected" : "failed"}`;
  databaseStatus.innerHTML = `
    <strong>${connected ? "Connected" : "Unavailable"}</strong>
    <span>${escapeHtml(database.message || database.status || "")}</span>
    <span>Schema: ${escapeHtml(database.schema || form.elements.postgresSchema.value || defaultValues.postgresSchema)}</span>
    <span>Branch rows: ${escapeHtml(String(database.branchRows ?? 0))}</span>
    <span>Flat rows: ${escapeHtml(String(database.flatRows ?? 0))}</span>
  `;
}

function renderLogs() {
  logsElement.textContent = state.logs.join("\n");
  logsElement.scrollTop = logsElement.scrollHeight;
  downloadLogsButton.disabled = state.logs.length === 0;
}

async function checkDatabase() {
  setDatabaseBusy(true);
  try {
    const response = await fetch("/api/database/status", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify(databasePayload()),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Database check failed.");
    }
    state.database = data.database;
    renderDatabaseStatus();
    notify(data.database && data.database.connected ? "Database connected." : "Database unavailable.");
  } catch (error) {
    state.database = {connected: false, message: error.message || "Database check failed."};
    renderDatabaseStatus();
    notify(error.message || "Database check failed.");
  } finally {
    setDatabaseBusy(false);
  }
}

async function exportDatabase(format) {
  setDatabaseBusy(true);
  try {
    const response = await fetch("/api/database/export", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({...databasePayload(), format}),
    });
    const contentType = response.headers.get("Content-Type") || "";
    if (!response.ok) {
      if (contentType.includes("application/json")) {
        const data = await response.json();
        throw new Error(data.error || "Database export failed.");
      }
      throw new Error("Database export failed.");
    }
    const blob = await response.blob();
    downloadBlob(blob, `application_inventory_database_export.${format}`);
    notify(`Database ${format.toUpperCase()} export downloaded.`);
  } catch (error) {
    notify(error.message || "Database export failed.");
  } finally {
    setDatabaseBusy(false);
  }
}

function formPayload() {
  const data = new FormData(form);
  const provider = data.get("provider") || "azure-devops";
  return {
    provider,
    org: value(data, "org"),
    adoOrgPats: provider === "azure-devops" ? value(data, "adoOrgPats") : "",
    targetFilters: targetFilterPayload(),
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
    postgresSchema: value(data, "postgresSchema") || defaultValues.postgresSchema,
    postgresTable: value(data, "postgresTable") || defaultValues.postgresTable,
    verbose: data.has("verbose"),
  };
}

function databasePayload() {
  const data = new FormData(form);
  return {
    postgresEnabled: data.has("postgresEnabled"),
    postgresHost: value(data, "postgresHost") || defaultValues.postgresHost,
    postgresPort: numberValue(data, "postgresPort", Number(defaultValues.postgresPort)),
    postgresDatabase: value(data, "postgresDatabase") || defaultValues.postgresDatabase,
    postgresUser: value(data, "postgresUser") || defaultValues.postgresUser,
    postgresPassword: value(data, "postgresPassword"),
    postgresSchema: value(data, "postgresSchema") || defaultValues.postgresSchema,
    postgresTable: value(data, "postgresTable") || defaultValues.postgresTable,
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
  form.querySelector('[name="org"]').required = provider === "github-enterprise";
  orgRequirementBadge.textContent = provider === "github-enterprise" ? "Required" : "Required unless using org PATs";
  form.querySelector('[name="project"]').required = false;
  form.querySelector('[name="repo"]').required = false;
  targetFilterTitle.textContent = provider === "github-enterprise" ? "Repository filter" : "Project filter";
  targetFilterDefault.textContent = provider === "github-enterprise" ? "Default: all repositories" : "Default: all projects";
  loadTargetsButton.textContent = provider === "github-enterprise" ? "Load repositories" : "Load projects";
  targetSearch.placeholder = provider === "github-enterprise" ? "Filter repositories" : "Filter projects";
  renderTargetFilters();
}

function syncDatabaseFields() {
  const enabled = form.querySelector('[name="postgresEnabled"]').checked;
  document.querySelectorAll(".database-fields").forEach((node) => {
    node.classList.toggle("hidden", !enabled);
  });
  for (const name of ["postgresHost", "postgresPort", "postgresDatabase", "postgresUser", "postgresSchema", "postgresTable"]) {
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
  const hasAdoOrgPats = provider === "azure-devops" && state.adoOrgPats.length > 0;
  form.elements.saveToken.disabled = !loggedIn || hasAdoOrgPats;
  if (!loggedIn || hasAdoOrgPats) {
    form.elements.saveToken.checked = false;
  }
  form.elements.token.placeholder = hasSavedToken ? "Uses saved token if blank" : "Uses environment token if blank";
  saveTokenHint.textContent = hasAdoOrgPats
    ? "Org PATs are used for this scan only"
    : loggedIn
    ? hasSavedToken
      ? "Saved token available for this provider"
      : "Checked tokens are encrypted and saved for your SSO user"
    : "Sign in to save or reuse provider tokens";
  forgetToken.classList.toggle("hidden", !loggedIn || !hasSavedToken);
}

function addAdoOrgPat() {
  commitPendingAdoOrgPat();
}

function commitPendingAdoOrgPat({silent = false} = {}) {
  const org = form.elements.adoOrgName.value.trim();
  const pat = form.elements.adoOrgPat.value.trim();
  if (!org && !pat) {
    return true;
  }
  if (!org || !pat) {
    notify("Add both an Azure organization and PAT.");
    return false;
  }
  const existingIndex = state.adoOrgPats.findIndex((entry) => entry.org.toLowerCase() === org.toLowerCase());
  const entry = {org, pat};
  if (existingIndex >= 0) {
    state.adoOrgPats.splice(existingIndex, 1, entry);
    if (!silent) {
      notify(`${org} updated.`);
    }
  } else {
    state.adoOrgPats.push(entry);
    if (!silent) {
      notify(`${org} added.`);
    }
  }
  form.elements.adoOrgName.value = "";
  form.elements.adoOrgPat.value = "";
  clearDiscoveredTargets({silent: true});
  syncAdoOrgPatInput();
  syncCredentialFields();
  return true;
}

function removeAdoOrgPat(org) {
  state.adoOrgPats = state.adoOrgPats.filter((entry) => entry.org !== org);
  clearDiscoveredTargets({silent: true});
  syncAdoOrgPatInput();
  syncCredentialFields();
  notify(`${org} removed.`);
}

function handleAdoOrgPatKeydown(event) {
  if (event.key !== "Enter") {
    return;
  }
  event.preventDefault();
  addAdoOrgPat();
}

function syncAdoOrgPatInput() {
  form.elements.adoOrgPats.value = JSON.stringify(state.adoOrgPats);
  renderAdoOrgPatList();
}

function renderAdoOrgPatList() {
  if (!state.adoOrgPats.length) {
    adoOrgPatList.innerHTML = '<div class="empty-inline">No Azure organizations added</div>';
    return;
  }
  adoOrgPatList.innerHTML = state.adoOrgPats.map((entry) => `
    <div class="ado-org-row">
      <span>
        <strong>${escapeHtml(entry.org)}</strong>
        <small>${escapeHtml(maskSecret(entry.pat))}</small>
      </span>
      <button class="ghost small" type="button" data-remove-ado-org="${escapeHtml(entry.org)}">Remove</button>
    </div>
  `).join("");
  adoOrgPatList.querySelectorAll("[data-remove-ado-org]").forEach((button) => {
    button.addEventListener("click", () => removeAdoOrgPat(button.dataset.removeAdoOrg || ""));
  });
}

async function loadSourceTargets() {
  if (!commitPendingAdoOrgPat({silent: true})) {
    return;
  }
  setTargetBusy(true);
  try {
    const response = await fetch("/api/source-targets", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify(sourcePayload()),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Could not load targets.");
    }
    state.sourceTargets = Array.isArray(data.targets) ? data.targets : [];
    state.sourceTargetErrors = Array.isArray(data.errors) ? data.errors : [];
    state.selectedTargets = state.selectedTargets.filter((selected) =>
      state.sourceTargets.some((target) => targetKey(target) === targetKey(selected)),
    );
    syncTargetFilterInput();
    if (state.sourceTargetErrors.length) {
      notify(`${state.sourceTargets.length} targets loaded with ${state.sourceTargetErrors.length} warning(s).`);
    } else {
      notify(`${state.sourceTargets.length} targets loaded.`);
    }
  } catch (error) {
    notify(error.message || "Could not load targets.");
  } finally {
    setTargetBusy(false);
  }
}

function sourcePayload() {
  const data = new FormData(form);
  const provider = data.get("provider") || "azure-devops";
  return {
    provider,
    org: value(data, "org"),
    adoOrgPats: provider === "azure-devops" ? value(data, "adoOrgPats") : "",
    baseUrl: provider === "github-enterprise" ? value(data, "baseUrl") : "",
    token: value(data, "token"),
    timeout: numberValue(data, "timeout", Number(defaultValues.timeout)),
  };
}

function setTargetBusy(isBusy) {
  loadTargetsButton.disabled = isBusy;
  selectAllTargetsButton.disabled = isBusy || visibleTargets().length === 0;
  clearTargetFiltersButton.disabled = isBusy || state.selectedTargets.length === 0;
  targetSearch.disabled = isBusy || state.sourceTargets.length === 0;
  if (isBusy) {
    targetFilterSummary.textContent = "Loading targets";
  } else {
    renderTargetFilters();
  }
}

function syncTargetFilterInput() {
  form.elements.targetFilters.value = JSON.stringify(targetFilterPayload());
  renderTargetFilters();
}

function targetFilterPayload() {
  return state.selectedTargets.map((target) => ({
    org: target.org || "",
    project: target.project || target.repo || target.name || "",
  }));
}

function renderTargetFilters() {
  if (!targetFilterList) {
    return;
  }
  const selectedCount = state.selectedTargets.length;
  const noun = providerTargetNoun();
  targetFilterSummary.textContent = selectedCount
    ? `${selectedCount} ${pluralize(noun, selectedCount)} selected`
    : `No ${pluralize(noun, 2)} selected`;
  selectAllTargetsButton.disabled = visibleTargets().length === 0;
  clearTargetFiltersButton.disabled = selectedCount === 0;
  targetSearch.disabled = state.sourceTargets.length === 0;

  if (!state.sourceTargets.length) {
    const warnings = renderTargetWarnings();
    targetFilterList.innerHTML = `${warnings}<div class="empty-inline">Load ${pluralize(noun, 2)} to choose a smaller scan scope</div>`;
    return;
  }

  const targets = visibleTargets();
  if (!targets.length) {
    targetFilterList.innerHTML = `${renderTargetWarnings()}<div class="empty-inline">No matches</div>`;
    return;
  }

  const selectedKeys = new Set(state.selectedTargets.map(targetKey));
  targetFilterList.innerHTML = `${renderTargetWarnings()}${targets.map((target) => {
    const checked = selectedKeys.has(targetKey(target)) ? " checked" : "";
    return `
      <label class="target-option">
        <input type="checkbox" value="${escapeHtml(targetKey(target))}"${checked}>
        <span>
          <strong>${escapeHtml(targetLabel(target))}</strong>
          <small>${escapeHtml(targetMeta(target))}</small>
        </span>
      </label>
    `;
  }).join("")}`;

  targetFilterList.querySelectorAll('.target-option input[type="checkbox"]').forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      const target = state.sourceTargets.find((candidate) => targetKey(candidate) === checkbox.value);
      if (!target) {
        return;
      }
      if (checkbox.checked) {
        addSelectedTarget(target);
      } else {
        removeSelectedTarget(target);
      }
      syncTargetFilterInput();
    });
  });
}

function renderTargetWarnings() {
  if (!state.sourceTargetErrors.length) {
    return "";
  }
  return `
    <div class="target-warning">
      ${state.sourceTargetErrors.map((error) => `
        <span>${escapeHtml(error.org || "Provider")}: ${escapeHtml(error.message || "Target load failed")}</span>
      `).join("")}
    </div>
  `;
}

function visibleTargets() {
  const query = targetSearch.value.trim().toLowerCase();
  if (!query) {
    return state.sourceTargets;
  }
  return state.sourceTargets.filter((target) =>
    `${target.org || ""} ${target.project || ""} ${target.label || ""}`.toLowerCase().includes(query),
  );
}

function selectVisibleTargets() {
  visibleTargets().forEach(addSelectedTarget);
  syncTargetFilterInput();
  notify(`${state.selectedTargets.length} ${pluralize(providerTargetNoun(), state.selectedTargets.length)} selected.`);
}

function clearSelectedTargets() {
  state.selectedTargets = [];
  syncTargetFilterInput();
  notify("Target filters cleared.");
}

function clearDiscoveredTargets({silent = false} = {}) {
  state.sourceTargets = [];
  state.selectedTargets = [];
  state.sourceTargetErrors = [];
  targetSearch.value = "";
  syncTargetFilterInput();
  if (!silent) {
    notify("Target filters cleared.");
  }
}

function addSelectedTarget(target) {
  const key = targetKey(target);
  if (!state.selectedTargets.some((selected) => targetKey(selected) === key)) {
    state.selectedTargets.push(normalizedTarget(target));
  }
}

function removeSelectedTarget(target) {
  const key = targetKey(target);
  state.selectedTargets = state.selectedTargets.filter((selected) => targetKey(selected) !== key);
}

function normalizedTarget(target) {
  return {
    org: target.org || "",
    project: target.project || target.repo || target.name || "",
    label: target.label || target.name || target.project || "",
    kind: target.kind || providerTargetNoun(),
  };
}

function targetKey(target) {
  return `${target.org || ""}\u001f${target.project || target.repo || target.name || ""}`;
}

function targetLabel(target) {
  return target.label || `${target.org || ""} / ${target.project || target.repo || target.name || ""}`;
}

function targetMeta(target) {
  const kind = target.kind === "repository" ? "Repository" : "Project";
  return `${kind} · ${target.org || "Unknown organization"}`;
}

function providerTargetNoun() {
  const provider = new FormData(form).get("provider") || "azure-devops";
  return provider === "github-enterprise" ? "repository" : "project";
}

function pluralize(noun, count) {
  if (count === 1) {
    return noun;
  }
  if (noun.endsWith("y")) {
    return `${noun.slice(0, -1)}ies`;
  }
  return `${noun}s`;
}

function sourceFieldChanged(target) {
  if (!target || !target.name) {
    return false;
  }
  return ["provider", "org", "baseUrl", "project", "repo", "token"].includes(target.name);
}

function loadForm() {
  const saved = JSON.parse(localStorage.getItem("application-inventory-service-ui") || "{}");
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
  localStorage.setItem("application-inventory-service-ui", JSON.stringify(saved));
}

function resetDefaults() {
  state.adoOrgPats = [];
  clearDiscoveredTargets({silent: true});
  applyDefaultValues();
  syncProviderFields();
  syncDatabaseFields();
  syncMobileOptions();
  syncAdoOrgPatInput();
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
  downloadBlob(blob, `${state.activeScan ? state.activeScan.id : "scan"}-logs.txt`);
}

function downloadBlob(blob, filename) {
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
  URL.revokeObjectURL(link.href);
}

function setBusy(isBusy) {
  startScanButton.disabled = isBusy;
  formStatus.textContent = isBusy ? "Starting" : "Ready";
  formStatus.className = `status-chip ${isBusy ? "status-running" : "idle"}`;
}

function setDatabaseBusy(isBusy) {
  checkDatabaseButton.disabled = isBusy;
  exportDatabaseCsvButton.disabled = isBusy;
  exportDatabaseJsonButton.disabled = isBusy;
}

function renderAuth() {
  const session = state.session || {};
  const loggedIn = Boolean(session.loggedIn);
  const providers = authProviders(session);
  const githubProvider = providers.find((provider) => provider.id === "github") || {};
  const googleProvider = providers.find((provider) => provider.id === "google") || {};
  const testProvider = providers.find((provider) => provider.id === "test") || {};
  const githubEnabled = Boolean(githubProvider.enabled);
  const enabledCount = providers.filter((provider) => provider.enabled).length;
  renderShell();
  authStatus.textContent = loggedIn
    ? `Signed in as ${session.user && session.user.login ? session.user.login : "SSO user"}`
    : enabledCount
      ? "Not signed in"
      : "SSO login not configured";
  loginSummary.textContent = enabledCount
    ? "Choose an enabled sign-in option."
    : "No sign-in options are configured for this instance.";
  loginGitHub.classList.toggle("hidden", loggedIn || !githubEnabled);
  loginGitHub.href = githubEnabled ? githubProvider.startUrl || "/api/auth/github/start" : "#";
  logoutGitHub.classList.toggle("hidden", !loggedIn);
  renderSsoOption(loginGitHubSso, githubSsoStatus, githubProvider, "GitHub");
  renderSsoOption(loginGoogleSso, googleSsoStatus, googleProvider, "Google");
  renderSsoOption(loginTestSso, testSsoStatus, testProvider, "Test user");
}

function renderShell() {
  const loggedIn = isLoggedIn();
  loginPage.hidden = loggedIn;
  appShell.hidden = !loggedIn;
  document.body.classList.toggle("login-mode", !loggedIn);
}

function renderSsoOption(link, statusElement, provider, label) {
  const enabled = Boolean(provider && provider.enabled);
  link.href = enabled ? provider.startUrl || `/api/auth/${provider.id}/start` : "#";
  link.classList.toggle("disabled", !enabled);
  link.setAttribute("aria-disabled", String(!enabled));
  statusElement.textContent = enabled ? "Available" : "Not configured";
  link.dataset.providerLabel = label;
}

function authProviders(session) {
  if (Array.isArray(session.authProviders) && session.authProviders.length) {
    return session.authProviders;
  }
  return [
    {
      id: "github",
      label: "GitHub SSO",
      enabled: Boolean(session.githubLoginEnabled),
      startUrl: "/api/auth/github/start",
    },
    {
      id: "google",
      label: "Google SSO",
      enabled: Boolean(session.googleLoginEnabled),
      startUrl: "/api/auth/google/start",
    },
    {
      id: "test",
      label: "Test User",
      enabled: Boolean(session.testLoginEnabled),
      startUrl: "/api/auth/test/start",
    },
  ];
}

function handleSsoClick(event) {
  const link = event.currentTarget;
  if (link.getAttribute("aria-disabled") !== "true") {
    return;
  }
  event.preventDefault();
  notify(`${link.dataset.providerLabel || "SSO"} is not configured.`);
}

function isLoggedIn() {
  return Boolean(state.session && state.session.loggedIn);
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
  const provider = authProviderName(params.get("provider"));
  if (auth === "success") {
    notify(`Signed in with ${provider}.`);
  } else if (auth === "failed") {
    notify(`${provider} sign-in failed.`);
  }
  if (auth) {
    window.history.replaceState({}, "", window.location.pathname);
  }
}

function authProviderName(provider) {
  if (provider === "google") {
    return "Google";
  }
  if (provider === "test") {
    return "test user";
  }
  return "GitHub";
}

function tick() {
  if (!isLoggedIn()) {
    return;
  }
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
    ml_enabled: "ML-enabled",
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

function maskSecret(value) {
  const text = String(value || "");
  if (text.length <= 4) {
    return "••••";
  }
  return `••••${text.slice(-4)}`;
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
