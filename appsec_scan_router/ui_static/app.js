const form = document.querySelector("#scanForm");
const loginPage = document.querySelector("#loginPage");
const appShell = document.querySelector("#appShell");
const startScanButton = document.querySelector("#startScan");
const startScanFormButton = document.querySelector("#startScanForm");
const stopScanButton = document.querySelector("#stopScan");
const pauseScanButton = document.querySelector("#pauseScan");
const resumeScanButton = document.querySelector("#resumeScan");
const refreshButton = document.querySelector("#refreshScans");
const resetDefaultsButton = document.querySelector("#resetDefaults");
const loginGitHubEnterpriseSso = document.querySelector("#loginGitHubEnterpriseSso");
const loginGoogleSso = document.querySelector("#loginGoogleSso");
const loginTestSso = document.querySelector("#loginTestSso");
const logoutGitHub = document.querySelector("#logoutGitHub");
const authStatus = document.querySelector("#authStatus");
const loginSummary = document.querySelector("#loginSummary");
const addGithubUrlButton = document.querySelector("#addGithubUrl");
const githubUrlList = document.querySelector("#githubUrlList");
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
const githubEnterpriseSsoStatus = document.querySelector("#githubEnterpriseSsoStatus");
const googleSsoStatus = document.querySelector("#googleSsoStatus");
const testSsoStatus = document.querySelector("#testSsoStatus");
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
const checkDatabaseButton = document.querySelector("#checkDatabase");
const exportDatabaseCsvButton = document.querySelector("#exportDatabaseCsv");
const exportDatabaseJsonButton = document.querySelector("#exportDatabaseJson");
const databaseStatus = document.querySelector("#databaseStatus");
const databaseSearchQuery = document.querySelector("#databaseSearchQuery");
const searchDatabaseButton = document.querySelector("#searchDatabase");
const clearDatabaseSearchButton = document.querySelector("#clearDatabaseSearch");
const databaseResultSummary = document.querySelector("#databaseResultSummary");
const databaseResultRows = document.querySelector("#databaseResultRows");
const databasePreviousButton = document.querySelector("#databasePrevious");
const databaseNextButton = document.querySelector("#databaseNext");
const databasePageSummary = document.querySelector("#databasePageSummary");
const tabButtons = document.querySelectorAll("[data-view]");
const createScheduleButton = document.querySelector("#createSchedule");
const scheduleName = document.querySelector("#scheduleName");
const scheduleFrequency = document.querySelector("#scheduleFrequency");
const scheduleRunAt = document.querySelector("#scheduleRunAt");
const scheduleCount = document.querySelector("#scheduleCount");
const scheduleList = document.querySelector("#scheduleList");

const state = {
  scans: [],
  activeScan: null,
  eventSource: null,
  logs: [],
  timer: null,
  session: null,
  database: null,
  databaseSearch: {query: "", rows: [], total: 0, limit: 100, offset: 0, loaded: false},
  githubUrls: [],
  adoOrgPats: [],
  sourceTargets: [],
  selectedTargets: [],
  sourceTargetErrors: [],
  schedules: [],
  pollTicks: 0,
};

const defaultValues = {
  githubUrls: [],
  githubRepositories: [],
  outPrefix: "application_inventory_service",
  applicationTypes: [],
  minConfidence: "medium",
  activityMode: "contributors",
  branchAgeDays: "90",
  sourceWorkers: "2",
  maxWorkers: "8",
  branchWorkers: "16",
  contentWorkers: "16",
  maxCommitsPerRepo: "0",
  timeout: "30",
  storeCountries: ["US"],
  storeTimeout: "15",
  storeLookup: false,
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
  "githubUrls",
  "applicationTypes",
  "minConfidence",
  "activityMode",
  "branchAgeDays",
  "sourceWorkers",
  "maxWorkers",
  "branchWorkers",
  "contentWorkers",
  "maxCommitsPerRepo",
  "timeout",
  "storeLookup",
  "storeCountries",
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
  await loadBackendConfig();
  loadForm();
  syncProviderFields();
  syncDatabaseFields();
  syncMobileOptions();
  syncAdoOrgPatInput();
  syncTargetFilterInput();
  setDefaultScheduleTime();
  bindEvents();
  renderShell();
  await loadSession();
  showAuthResult();
  if (isLoggedIn()) {
    await Promise.all([loadScans(), loadSchedules()]);
  } else {
    renderAll();
  }
  state.timer = window.setInterval(tick, 1000);
});

async function loadBackendConfig() {
  try {
    const response = await fetch("/api/config");
    const data = await response.json();
    if (response.ok && data.defaults) {
      Object.assign(defaultValues, data.defaults);
    }
  } catch (error) {
    return;
  }
}

function bindEvents() {
  form.addEventListener("change", (event) => {
    if (sourceFieldChanged(event.target)) {
      clearDiscoveredTargets({silent: true});
    }
    syncProviderFields();
    syncDatabaseFields();
    syncMobileOptions();
    saveForm();
  });
  form.addEventListener("input", saveForm);
  startScanButton.addEventListener("click", startScan);
  startScanFormButton.addEventListener("click", startScan);
  stopScanButton.addEventListener("click", stopScan);
  pauseScanButton.addEventListener("click", () => controlScan("pause"));
  resumeScanButton.addEventListener("click", () => controlScan("resume"));
  refreshButton.addEventListener("click", refreshData);
  createScheduleButton.addEventListener("click", createSchedule);
  resetDefaultsButton.addEventListener("click", resetDefaults);
  addAdoOrgPatButton.addEventListener("click", addAdoOrgPat);
  addGithubUrlButton.addEventListener("click", addGithubUrl);
  loadTargetsButton.addEventListener("click", loadSourceTargets);
  selectAllTargetsButton.addEventListener("click", selectVisibleTargets);
  clearTargetFiltersButton.addEventListener("click", () => clearSelectedTargets());
  targetSearch.addEventListener("input", renderTargetFilters);
  form.elements.adoOrgName.addEventListener("keydown", handleAdoOrgPatKeydown);
  form.elements.adoOrgPat.addEventListener("keydown", handleAdoOrgPatKeydown);
  form.elements.githubUrl.addEventListener("keydown", handleGithubUrlKeydown);
  logoutGitHub.addEventListener("click", logout);
  loginGitHubEnterpriseSso.addEventListener("click", handleSsoClick);
  loginGoogleSso.addEventListener("click", handleSsoClick);
  loginTestSso.addEventListener("click", handleSsoClick);
  copyCommandButton.addEventListener("click", copyCommand);
  clearLogsButton.addEventListener("click", () => {
    state.logs = [];
    renderLogs();
  });
  downloadLogsButton.addEventListener("click", downloadLogs);
  checkDatabaseButton.addEventListener("click", checkDatabase);
  searchDatabaseButton.addEventListener("click", () => searchDatabase(0, databaseSearchQuery.value));
  clearDatabaseSearchButton.addEventListener("click", () => {
    databaseSearchQuery.value = "";
    searchDatabase(0, "");
  });
  databaseSearchQuery.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      searchDatabase(0, databaseSearchQuery.value);
    }
  });
  databasePreviousButton.addEventListener("click", () => {
    const search = state.databaseSearch;
    searchDatabase(Math.max(0, search.offset - search.limit), search.query);
  });
  databaseNextButton.addEventListener("click", () => {
    const search = state.databaseSearch;
    searchDatabase(search.offset + search.limit, search.query);
  });
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
  if (!ensureAdoOrgPats()) {
    return;
  }
  if (!ensureGithubUrls()) {
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
    state.activeScan = stampScan(data.scan);
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
  await controlScan("stop");
}

async function controlScan(action) {
  if (!state.activeScan) {
    return;
  }
  try {
    const response = await fetch(`/api/scans/${state.activeScan.id}/${action}`, {
      method: "POST",
      headers: authHeaders(false),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || `${capitalize(action)} failed.`);
    }
    state.activeScan = stampScan(data.scan);
    mergeScan(state.activeScan);
    renderAll();
    notify(action === "stop" ? "Stop requested." : `Scan ${action}d.`);
  } catch (error) {
    notify(error.message || `${capitalize(action)} failed.`);
  }
}

async function loadSession() {
  try {
    const response = await fetch("/api/session");
    const data = await response.json();
    state.session = data.session || null;
    renderAuth();
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
    state.database = null;
    state.databaseSearch = {query: "", rows: [], total: 0, limit: 100, offset: 0, loaded: false};
    databaseSearchQuery.value = "";
    state.githubUrls = [...defaultValues.githubUrls];
    state.adoOrgPats = [];
    clearDiscoveredTargets({silent: true});
    syncGithubUrlInput();
    syncAdoOrgPatInput();
    renderAuth();
    renderAll();
    notify("Signed out.");
  } catch (error) {
    notify(error.message || "Sign out failed.");
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
    state.scans = (data.scans || []).map(stampScan);
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
    state.activeScan = stampScan(data.scan || scan);
    state.logs = state.activeScan.logsTail || [];
    renderAll();
    if (connect && ["running", "paused"].includes(state.activeScan.status)) {
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
    state.activeScan = stampScan(JSON.parse(event.data));
    mergeScan(state.activeScan);
    renderAll();
  });
  source.addEventListener("log", (event) => {
    const data = JSON.parse(event.data);
    if (data.line) {
      state.logs.push(data.line);
      if (state.logs.length > 1300) {
        state.logs = state.logs.slice(-1200);
        renderLogs();
      } else {
        appendLogLine(data.line);
      }
    }
  });
  source.addEventListener("done", async (event) => {
    state.activeScan = stampScan(JSON.parse(event.data));
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
  stampScan(scan);
  const index = state.scans.findIndex((candidate) => candidate.id === scan.id);
  if (index >= 0) {
    state.scans.splice(index, 1, scan);
  } else {
    state.scans.unshift(scan);
  }
}

function stampScan(scan) {
  if (scan) {
    scan.observedAt = Date.now();
  }
  return scan;
}

async function refreshData() {
  await Promise.all([loadScans(), loadSchedules()]);
}

function renderAll() {
  renderActiveScan();
  renderRuns();
  renderReports();
  renderSchedules();
  renderDatabaseStatus();
  renderDatabaseResults();
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
    commandLine.textContent = "application-inventory-service";
    copyCommandButton.disabled = true;
    pauseScanButton.disabled = true;
    resumeScanButton.disabled = true;
    resumeScanButton.classList.add("hidden");
    pauseScanButton.classList.remove("hidden");
    stopScanButton.disabled = true;
    downloadLogsButton.disabled = true;
    return;
  }
  activeStatus.textContent = capitalize(scan.status);
  activeStatus.className = `status-${scan.status}`;
  activeTitle.textContent = `${scan.org || "Unknown"} · ${scan.target || "all"} · ${providerLabel(scan.provider)} · ${applicationTypesLabel(scan.applicationTypes)}`;
  detectedCount.textContent = String(scan.detectedCount || 0);
  runtimeValue.textContent = scanRuntime(scan);
  commandLine.textContent = scan.command || "application-inventory-service";
  copyCommandButton.disabled = !scan.command;
  const paused = scan.status === "paused";
  pauseScanButton.classList.toggle("hidden", paused);
  pauseScanButton.disabled = scan.status !== "running";
  resumeScanButton.classList.toggle("hidden", !paused);
  resumeScanButton.disabled = !paused;
  stopScanButton.disabled = !["queued", "running", "paused"].includes(scan.status);
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

async function loadSchedules() {
  if (!isLoggedIn()) {
    state.schedules = [];
    renderSchedules();
    return;
  }
  try {
    const response = await fetch("/api/schedules");
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Could not load schedules.");
    }
    state.schedules = data.schedules || [];
    renderSchedules();
  } catch (error) {
    notify(error.message || "Could not load schedules.");
  }
}

async function createSchedule() {
  if (!commitPendingAdoOrgPat({silent: true}) || !ensureAdoOrgPats() || !ensureGithubUrls()) {
    return;
  }
  if (!form.reportValidity()) {
    setActiveView("setupView");
    return;
  }
  const name = scheduleName.value.trim();
  const localRunAt = scheduleRunAt.value;
  if (!name) {
    scheduleName.focus();
    notify("Enter a schedule name.");
    return;
  }
  if (!localRunAt) {
    scheduleRunAt.focus();
    notify("Choose the first run time.");
    return;
  }
  const runAt = new Date(localRunAt);
  if (!Number.isFinite(runAt.getTime()) || runAt.getTime() < Date.now() - 5000) {
    scheduleRunAt.focus();
    notify("Choose a future run time.");
    return;
  }
  createScheduleButton.disabled = true;
  try {
    const response = await fetch("/api/schedules", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({
        name,
        frequency: scheduleFrequency.value,
        runAt: runAt.toISOString(),
        scan: formPayload(),
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Schedule could not be created.");
    }
    scheduleName.value = "";
    setDefaultScheduleTime();
    await loadSchedules();
    notify("Schedule created.");
  } catch (error) {
    notify(error.message || "Schedule could not be created.");
  } finally {
    createScheduleButton.disabled = false;
  }
}

function renderSchedules() {
  scheduleCount.textContent = String(state.schedules.length);
  if (!state.schedules.length) {
    scheduleList.innerHTML = '<div class="empty-state">No schedules</div>';
    return;
  }
  scheduleList.innerHTML = state.schedules.map((schedule) => `
    <article class="schedule-item">
      <div class="schedule-item-heading">
        <span>
          <strong>${escapeHtml(schedule.name)}</strong>
          <small>${escapeHtml(providerLabel(schedule.provider))} · ${escapeHtml(schedule.org || "All sources")} · ${escapeHtml(schedule.target || "all")}</small>
        </span>
        <span class="status-chip ${schedule.enabled ? "status-running" : "status-idle"}">${schedule.enabled ? "Enabled" : "Disabled"}</span>
      </div>
      <dl class="schedule-meta">
        <div><dt>Frequency</dt><dd>${escapeHtml(capitalize(schedule.frequency))}</dd></div>
        <div><dt>Next run</dt><dd>${escapeHtml(schedule.enabled ? formatDate(schedule.nextRunAt) : "Not scheduled")}</dd></div>
        <div><dt>Last run</dt><dd>${escapeHtml(formatDate(schedule.lastRunAt) || "Never")}</dd></div>
      </dl>
      ${schedule.lastError ? `<p class="schedule-error">${escapeHtml(schedule.lastError)}</p>` : ""}
      <div class="schedule-actions">
        <button class="ghost small" type="button" data-schedule-action="run" data-schedule-id="${escapeHtml(schedule.id)}">Run now</button>
        <button class="ghost small" type="button" data-schedule-action="${schedule.enabled ? "disable" : "enable"}" data-schedule-id="${escapeHtml(schedule.id)}">${schedule.enabled ? "Disable" : "Enable"}</button>
        <button class="danger small" type="button" data-schedule-action="delete" data-schedule-id="${escapeHtml(schedule.id)}">Delete</button>
      </div>
    </article>
  `).join("");
  scheduleList.querySelectorAll("[data-schedule-action]").forEach((button) => {
    button.addEventListener("click", () => updateSchedule(button.dataset.scheduleId, button.dataset.scheduleAction));
  });
}

async function updateSchedule(scheduleId, action) {
  const method = action === "delete" ? "DELETE" : "POST";
  const path = action === "delete" ? `/api/schedules/${scheduleId}` : `/api/schedules/${scheduleId}/${action}`;
  try {
    const response = await fetch(path, {method, headers: authHeaders(false)});
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Schedule update failed.");
    }
    await Promise.all([loadSchedules(), action === "run" ? loadScans() : Promise.resolve()]);
    notify(action === "run" ? "Scheduled scan queued." : `Schedule ${action}d.`);
  } catch (error) {
    notify(error.message || "Schedule update failed.");
  }
}

function setDefaultScheduleTime() {
  const date = new Date(Date.now() + 60 * 60 * 1000);
  date.setMinutes(0, 0, 0);
  const offset = date.getTimezoneOffset() * 60 * 1000;
  scheduleRunAt.value = new Date(date.getTime() - offset).toISOString().slice(0, 16);
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

function renderDatabaseResults() {
  const search = state.databaseSearch;
  if (!search.loaded) {
    databaseResultSummary.textContent = "Search to view inventory records";
    databaseResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="12">No search has been run.</td></tr>';
    databasePageSummary.textContent = "Page 1";
    databasePreviousButton.disabled = true;
    databaseNextButton.disabled = true;
    return;
  }
  const start = search.total ? search.offset + 1 : 0;
  const end = Math.min(search.offset + search.rows.length, search.total);
  const filterLabel = search.query ? ` matching "${search.query}"` : "";
  databaseResultSummary.textContent = `Showing ${start}-${end} of ${search.total}${filterLabel}`;
  if (!search.rows.length) {
    databaseResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="12">No inventory records match this search.</td></tr>';
  } else {
    databaseResultRows.innerHTML = search.rows.map((row) => `
      <tr>
        <td>${databaseCell(providerLabel(row.provider))}</td>
        <td>${databaseCell(row.organization)}</td>
        <td>${databaseCell(row.project)}</td>
        <td>${databaseCell(row.repo_name)}</td>
        <td>${databaseCell(row.branch_name)}</td>
        <td>${databaseDomainCell(row)}</td>
        <td>${databaseCell(row.inventory_name || row.mobile_name)}</td>
        <td>${databaseCell(row.inventory_version || row.mobile_version)}</td>
        <td>${databaseCell(row.primary_language)}</td>
        <td>${databaseCell(formatDate(row.branch_last_updated || row.last_updated))}</td>
        <td>${databaseCell(row.confidence)}</td>
        <td>${databaseCell(row.inventory_types)}</td>
      </tr>
    `).join("");
  }
  const page = search.total ? Math.floor(search.offset / search.limit) + 1 : 1;
  const pages = Math.max(1, Math.ceil(search.total / search.limit));
  databasePageSummary.textContent = `Page ${page} of ${pages}`;
  databasePreviousButton.disabled = search.offset <= 0;
  databaseNextButton.disabled = search.offset + search.rows.length >= search.total;
}

function databaseCell(value) {
  const text = String(value || "").trim();
  return escapeHtml(text || "Not detected");
}

function databaseDomainCell(row) {
  const domain = String(row.primary_web_domain || "").trim();
  if (!domain) {
    return '<span class="database-domain-empty">Not detected</span>';
  }
  const status = String(row.web_domain_status || "configured").trim();
  return `<span class="database-domain-value">${escapeHtml(domain)}</span><small class="database-domain-status">${escapeHtml(capitalize(status))}</small>`;
}

function renderLogs() {
  const fragment = document.createDocumentFragment();
  state.logs.forEach((line, index) => {
    if (index > 0) {
      fragment.append(document.createTextNode("\n"));
    }
    const element = document.createElement("span");
    element.className = logTone(line);
    element.textContent = line;
    fragment.append(element);
  });
  logsElement.replaceChildren(fragment);
  logsElement.scrollTop = logsElement.scrollHeight;
  downloadLogsButton.disabled = state.logs.length === 0;
}

function appendLogLine(line) {
  if (logsElement.childNodes.length) {
    logsElement.append(document.createTextNode("\n"));
  }
  const element = document.createElement("span");
  element.className = logTone(line);
  element.textContent = line;
  logsElement.append(element);
  logsElement.scrollTop = logsElement.scrollHeight;
  downloadLogsButton.disabled = false;
}

function logTone(line) {
  const value = String(line || "").toLowerCase();
  if (/\b(error|failed|failure|exception|traceback|fatal)\b|could not|unable to|missing .* configuration/.test(value)) {
    return "log-error";
  }
  if (/\b(detected|confirmed|match)\b|found \d+ inventory/.test(value)) {
    return "log-success";
  }
  return "";
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

async function searchDatabase(offset = 0, query = "") {
  setDatabaseBusy(true);
  try {
    const response = await fetch("/api/database/search", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({...databasePayload(), query, offset, limit: state.databaseSearch.limit}),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Database search failed.");
    }
    state.databaseSearch = {...data.search, loaded: true};
    databaseSearchQuery.value = data.search.query || "";
    renderDatabaseResults();
  } catch (error) {
    notify(error.message || "Database search failed.");
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
      body: JSON.stringify({...databasePayload(), format, query: state.databaseSearch.query}),
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
    org: isGithubProvider(provider) ? state.githubUrls[0] || "" : "",
    githubUrls: isGithubProvider(provider) ? state.githubUrls : [],
    adoOrgPats: isAzureProvider(provider) ? value(data, "adoOrgPats") : "",
    targetFilters: targetFilterPayload(),
    project: "",
    outPrefix: defaultValues.outPrefix,
    applicationTypes: checkedValues("applicationTypes"),
    minConfidence: value(data, "minConfidence") || defaultValues.minConfidence,
    activityMode: value(data, "activityMode") || defaultValues.activityMode,
    branchAgeDays: numberValue(data, "branchAgeDays", Number(defaultValues.branchAgeDays)),
    sourceWorkers: numberValue(data, "sourceWorkers", Number(defaultValues.sourceWorkers)),
    maxWorkers: numberValue(data, "maxWorkers", Number(defaultValues.maxWorkers)),
    branchWorkers: numberValue(data, "branchWorkers", Number(defaultValues.branchWorkers)),
    contentWorkers: numberValue(data, "contentWorkers", Number(defaultValues.contentWorkers)),
    maxCommitsPerRepo: numberValue(data, "maxCommitsPerRepo", Number(defaultValues.maxCommitsPerRepo)),
    timeout: numberValue(data, "timeout", Number(defaultValues.timeout)),
    storeLookup: data.has("storeLookup"),
    storeCountries: checkedValues("storeCountries").length ? checkedValues("storeCountries") : [...defaultValues.storeCountries],
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
    node.classList.toggle("hidden", !isAzureProvider(provider));
  });
  document.querySelectorAll(".provider-github").forEach((node) => {
    node.classList.toggle("hidden", !isGithubProvider(provider));
  });
  form.elements.githubUrl.required = false;
  document.querySelector("#adoOrgLabel").textContent = "Azure organizations and PATs";
  document.querySelector("#adoOrgRequirementBadge").textContent = "Required";
  targetFilterTitle.textContent = provider === "github-enterprise" ? "Repository filter" : provider === "mixed" ? "Project and repository filter" : "Project filter";
  targetFilterDefault.textContent = provider === "github-enterprise"
    ? (defaultValues.githubRepositories.length ? "Default: configured repositories" : "Default: all repositories")
    : provider === "mixed"
      ? "Default: all selected sources"
      : "Default: all projects";
  loadTargetsButton.textContent = provider === "github-enterprise" ? "Load repositories" : provider === "mixed" ? "Load all targets" : "Load projects";
  targetSearch.placeholder = provider === "github-enterprise" ? "Filter repositories" : provider === "mixed" ? "Filter projects and repositories" : "Filter projects";
  syncGithubAppFields();
  renderTargetFilters();
}

function syncGithubAppFields() {
  const enabled = isGithubProvider(new FormData(form).get("provider") || "azure-devops");
  document.querySelectorAll(".github-app-status").forEach((node) => {
    node.classList.toggle("hidden", !enabled);
  });
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

function addGithubUrl() {
  commitPendingGithubUrl();
}

function ensureGithubUrls() {
  const provider = new FormData(form).get("provider") || "azure-devops";
  if (!isGithubProvider(provider) || state.githubUrls.length > 0) {
    return true;
  }
  form.elements.githubUrl.focus();
  notify("Add at least one GitHub URL.");
  return false;
}

function commitPendingGithubUrl({silent = false} = {}) {
  const url = form.elements.githubUrl.value.trim();
  if (!url) {
    return true;
  }
  if (state.githubUrls.some((entry) => entry.toLowerCase() === url.toLowerCase())) {
    notify(`${url} is already added.`);
    return false;
  }
  state.githubUrls.push(url);
  form.elements.githubUrl.value = "";
  clearDiscoveredTargets({silent: true});
  syncGithubUrlInput();
  if (!silent) {
    notify(`${url} added.`);
  }
  return true;
}

function removeGithubUrl(url) {
  state.githubUrls = state.githubUrls.filter((entry) => entry !== url);
  clearDiscoveredTargets({silent: true});
  syncGithubUrlInput();
  notify(`${url} removed.`);
}

function handleGithubUrlKeydown(event) {
  if (event.key !== "Enter") {
    return;
  }
  event.preventDefault();
  addGithubUrl();
}

function syncGithubUrlInput() {
  form.elements.githubUrls.value = JSON.stringify(state.githubUrls);
  renderGithubUrlList();
}

function renderGithubUrlList() {
  if (!state.githubUrls.length) {
    githubUrlList.innerHTML = '<div class="empty-inline">No GitHub URLs added</div>';
    return;
  }
  githubUrlList.innerHTML = state.githubUrls.map((url) => `
    <div class="github-url-row">
      <span><strong>${escapeHtml(url)}</strong></span>
      <button class="ghost small" type="button" data-remove-github-url="${escapeHtml(url)}">Remove</button>
    </div>
  `).join("");
  githubUrlList.querySelectorAll("[data-remove-github-url]").forEach((button) => {
    button.addEventListener("click", () => removeGithubUrl(button.dataset.removeGithubUrl || ""));
  });
}

function addAdoOrgPat() {
  commitPendingAdoOrgPat();
}

function ensureAdoOrgPats() {
  const provider = new FormData(form).get("provider") || "azure-devops";
  if (!isAzureProvider(provider) || state.adoOrgPats.length > 0) {
    return true;
  }
  form.elements.adoOrgName.focus();
  notify("Add at least one Azure organization and PAT.");
  return false;
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
  return true;
}

function removeAdoOrgPat(org) {
  state.adoOrgPats = state.adoOrgPats.filter((entry) => entry.org !== org);
  clearDiscoveredTargets({silent: true});
  syncAdoOrgPatInput();
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
  if (!ensureAdoOrgPats()) {
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
      const providerErrors = Array.isArray(data.errors) ? data.errors.map((item) => item.message).filter(Boolean).join("; ") : "";
      throw new Error(data.error || providerErrors || "Could not load targets.");
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
    org: isGithubProvider(provider) ? state.githubUrls[0] || "" : "",
    githubUrls: isGithubProvider(provider) ? state.githubUrls : [],
    adoOrgPats: isAzureProvider(provider) ? value(data, "adoOrgPats") : "",
    timeout: numberValue(data, "timeout", Number(defaultValues.timeout)),
    sourceWorkers: numberValue(data, "sourceWorkers", Number(defaultValues.sourceWorkers)),
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
  return provider === "github-enterprise" ? "repository" : provider === "mixed" ? "target" : "project";
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
  return ["provider", "githubUrl"].includes(target.name);
}

function loadForm() {
  const saved = JSON.parse(localStorage.getItem("application-inventory-service-ui") || "{}");
  applyDefaultValues();
  for (const name of persistedFields) {
    if (!(name in saved)) {
      continue;
    }
    if (name === "githubUrls") {
      state.githubUrls = Array.isArray(saved[name]) ? saved[name].map((item) => String(item || "").trim()).filter(Boolean) : [...defaultValues.githubUrls];
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
  syncGithubUrlInput();
}

function saveForm() {
  const data = new FormData(form);
  const saved = {};
  for (const name of persistedFields) {
    if (name === "provider") {
      saved[name] = data.get(name);
    } else if (name === "githubUrls") {
      saved[name] = [...state.githubUrls];
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
  state.githubUrls = [...defaultValues.githubUrls];
  state.adoOrgPats = [];
  clearDiscoveredTargets({silent: true});
  applyDefaultValues();
  syncProviderFields();
  syncDatabaseFields();
  syncMobileOptions();
  syncGithubUrlInput();
  syncAdoOrgPatInput();
  saveForm();
  notify("Scan defaults restored.");
}

function applyDefaultValues() {
  for (const [name, defaultValue] of Object.entries(defaultValues)) {
    if (name === "githubUrls") {
      state.githubUrls = [...defaultValue];
      continue;
    }
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
  startScanFormButton.disabled = isBusy;
  formStatus.textContent = isBusy ? "Starting" : "Ready";
  formStatus.className = `status-chip ${isBusy ? "status-running" : "idle"}`;
}

function setDatabaseBusy(isBusy) {
  checkDatabaseButton.disabled = isBusy;
  searchDatabaseButton.disabled = isBusy;
  clearDatabaseSearchButton.disabled = isBusy;
  exportDatabaseCsvButton.disabled = isBusy;
  exportDatabaseJsonButton.disabled = isBusy;
  if (isBusy) {
    databasePreviousButton.disabled = true;
    databaseNextButton.disabled = true;
  } else {
    renderDatabaseResults();
  }
}

function renderAuth() {
  const session = state.session || {};
  const loggedIn = Boolean(session.loggedIn);
  const providers = authProviders(session);
  const githubEnterpriseProvider = providers.find((provider) => provider.id === "github-enterprise") || {};
  const googleProvider = providers.find((provider) => provider.id === "google") || {};
  const testProvider = providers.find((provider) => provider.id === "test") || {};
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
  logoutGitHub.classList.toggle("hidden", !loggedIn);
  renderSsoOption(loginGitHubEnterpriseSso, githubEnterpriseSsoStatus, githubEnterpriseProvider, "GitHub Enterprise");
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
      id: "github-enterprise",
      label: "GitHub Enterprise",
      enabled: Boolean(session.githubEnterpriseLoginEnabled),
      startUrl: "/api/auth/github-enterprise/start",
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
  state.pollTicks += 1;
  if (state.pollTicks >= 30 && !document.hidden) {
    state.pollTicks = 0;
    refreshData();
  }
}

function scanRuntime(scan) {
  if (Number.isFinite(Number(scan.activeSeconds))) {
    let seconds = Number(scan.activeSeconds);
    if (scan.status === "running" && scan.observedAt) {
      seconds += Math.max(0, Math.floor((Date.now() - scan.observedAt) / 1000));
    }
    return formatDuration(seconds);
  }
  if (!scan.startedAt) {
    return "0s";
  }
  const start = Date.parse(scan.startedAt);
  const end = scan.endedAt ? Date.parse(scan.endedAt) : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end)) {
    return "0s";
  }
  const total = Math.max(0, Math.floor((end - start) / 1000));
  return formatDuration(total);
}

function formatDuration(value) {
  const total = Math.max(0, Math.floor(Number(value) || 0));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  if (hours) {
    return `${hours}h ${minutes}m`;
  }
  return minutes ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

function providerLabel(provider) {
  if (provider === "github-enterprise") {
    return "GitHub Enterprise";
  }
  if (provider === "mixed") {
    return "Azure DevOps + GitHub Enterprise";
  }
  return "Azure DevOps";
}

function isAzureProvider(provider) {
  return provider === "azure-devops" || provider === "mixed";
}

function isGithubProvider(provider) {
  return provider === "github-enterprise" || provider === "mixed";
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
