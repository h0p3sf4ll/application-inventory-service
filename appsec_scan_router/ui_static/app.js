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
const clearFailuresButton = document.querySelector("#clearFailures");
const downloadFailuresButton = document.querySelector("#downloadFailures");
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
const failuresElement = document.querySelector("#failures");
const failureCount = document.querySelector("#failureCount");
const toast = document.querySelector("#toast");
const formStatus = document.querySelector("#formStatus");
const checkDatabaseButton = document.querySelector("#checkDatabase");
const databaseReadyBadge = document.querySelector("#databaseReadyBadge");
const exportDatabaseXlsxButton = document.querySelector("#exportDatabaseXlsx");
const exportDatabaseCsvButton = document.querySelector("#exportDatabaseCsv");
const exportDatabaseJsonButton = document.querySelector("#exportDatabaseJson");
const databaseStatus = document.querySelector("#databaseStatus");
const databaseLiveStatus = document.querySelector("#databaseLiveStatus");
const databaseSearchQuery = document.querySelector("#databaseSearchQuery");
const searchDatabaseButton = document.querySelector("#searchDatabase");
const clearDatabaseSearchButton = document.querySelector("#clearDatabaseSearch");
const databaseResultSummary = document.querySelector("#databaseResultSummary");
const databaseResultRows = document.querySelector("#databaseResultRows");
const databasePreviousButton = document.querySelector("#databasePrevious");
const databaseNextButton = document.querySelector("#databaseNext");
const databasePagePosition = document.querySelector("#databasePagePosition");
const databaseRecordCount = document.querySelector("#databaseRecordCount");
const inventoryFilterButtons = document.querySelectorAll("[data-inventory-filter]");
const databaseSortButtons = document.querySelectorAll("[data-database-sort]");
const databaseColumnFilters = {
  application: document.querySelector("#filterApplication"),
  repository: document.querySelector("#filterRepository"),
  branch: document.querySelector("#filterBranch"),
  domain: document.querySelector("#filterDomain"),
  updated: document.querySelector("#filterUpdated"),
  confidence: document.querySelector("#filterConfidence"),
  source: document.querySelector("#filterSource"),
};
const databaseTypeFilter = document.querySelector("#filterType");
const databaseTypeFilterSummary = document.querySelector("#filterTypeSummary");
const databaseTypeCheckboxes = Array.from(document.querySelectorAll('input[name="databaseFilterType"]'));
const clearDatabaseTypeFilterButton = document.querySelector("#clearFilterTypes");
const databaseLanguageFilter = document.querySelector("#filterLanguage");
const databaseLanguageFilterSummary = document.querySelector("#filterLanguageSummary");
const databaseLanguageOptions = document.querySelector("#filterLanguageOptions");
const databaseLanguageEmpty = document.querySelector("#filterLanguageEmpty");
const clearDatabaseLanguageFilterButton = document.querySelector("#clearFilterLanguages");
const localLlmStatus = document.querySelector("#localLlmStatus");
const inventoryAssistantQuery = document.querySelector("#inventoryAssistantQuery");
const askInventoryButton = document.querySelector("#askInventory");
const inventoryAssistantSummary = document.querySelector("#inventoryAssistantSummary");
const inventoryRecordDialog = document.querySelector("#inventoryRecordDialog");
const inventoryRecordTitle = document.querySelector("#inventoryRecordTitle");
const inventoryRecordDetails = document.querySelector("#inventoryRecordDetails");
const closeInventoryRecordButton = document.querySelector("#closeInventoryRecord");
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
  eventSourceScanId: "",
  eventSourceStartedAt: 0,
  eventSourceLastEventAt: 0,
  logs: [],
  failures: [],
  logSequence: 0,
  failureSequence: 0,
  timer: null,
  session: null,
  database: null,
  databaseSearch: {query: "", filters: {}, rows: [], total: 0, limit: 100, offset: 0, loaded: false},
  databaseFacets: {languages: [], loaded: false},
  databaseSearchBusy: false,
  databaseConfigDirty: true,
  databaseRefreshTimer: null,
  localLlm: null,
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
  postgresPassword: "postgres",
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
    await Promise.all([loadScans(), loadSchedules(), initializeDatabase()]);
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
    state.database = data.database || null;
    state.localLlm = data.localLlm || null;
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
  form.addEventListener("input", (event) => {
    saveForm();
    if (databaseFieldChanged(event.target)) {
      state.databaseConfigDirty = true;
      resetDatabaseFacets();
      scheduleDatabaseConnectionCheck();
    }
  });
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
  clearFailuresButton.addEventListener("click", () => {
    state.failures = [];
    renderFailures();
  });
  downloadFailuresButton.addEventListener("click", downloadFailures);
  checkDatabaseButton.addEventListener("click", () => checkDatabase());
  searchDatabaseButton.addEventListener("click", () => searchDatabase(0, databaseSearchQuery.value));
  clearDatabaseSearchButton.addEventListener("click", () => {
    databaseSearchQuery.value = "";
    resetDatabaseColumnFilters();
    activateInventoryFilter("all");
  });
  databaseSearchQuery.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      searchDatabase(0, databaseSearchQuery.value);
    }
  });
  databasePreviousButton.addEventListener("click", () => {
    const search = state.databaseSearch;
    searchDatabase(Math.max(0, search.offset - search.limit), search.query, {filters: search.filters});
  });
  databaseNextButton.addEventListener("click", () => {
    const search = state.databaseSearch;
    searchDatabase(search.offset + search.limit, search.query, {filters: search.filters});
  });
  exportDatabaseXlsxButton.addEventListener("click", () => exportDatabase("xlsx"));
  exportDatabaseCsvButton.addEventListener("click", () => exportDatabase("csv"));
  exportDatabaseJsonButton.addEventListener("click", () => exportDatabase("json"));
  inventoryFilterButtons.forEach((button) => {
    button.addEventListener("click", () => activateInventoryFilter(button.dataset.inventoryFilter));
  });
  databaseSortButtons.forEach((button) => {
    button.addEventListener("click", () => sortDatabase(button.dataset.databaseSort));
  });
  Object.values(databaseColumnFilters).forEach((control) => {
    control.addEventListener(control.matches("select") ? "change" : "input", scheduleColumnFilterSearch);
    control.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        applyDatabaseColumnFilters();
      }
    });
  });
  databaseTypeCheckboxes.forEach((checkbox) => {
    checkbox.addEventListener("change", (event) => {
      renderDatabaseTypeFilter();
      scheduleColumnFilterSearch(event);
    });
  });
  databaseLanguageOptions.addEventListener("change", (event) => {
    if (!event.target.matches('input[name="databaseFilterLanguage"]')) {
      return;
    }
    renderDatabaseLanguageFilterSummary();
    scheduleColumnFilterSearch(event);
  });
  clearDatabaseTypeFilterButton.addEventListener("click", () => {
    setDatabaseTypeFilters([]);
    setActiveInventoryFilterButton("");
    applyDatabaseColumnFilters();
  });
  clearDatabaseLanguageFilterButton.addEventListener("click", () => {
    setDatabaseLanguageFilters([]);
    setActiveInventoryFilterButton("");
    applyDatabaseColumnFilters();
  });
  [databaseTypeFilter, databaseLanguageFilter].forEach((filter) => filter.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      filter.open = false;
      filter.querySelector("summary").focus();
    }
  }));
  document.addEventListener("click", (event) => {
    [databaseTypeFilter, databaseLanguageFilter].forEach((filter) => {
      if (filter.open && !filter.contains(event.target)) {
        filter.open = false;
      }
    });
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && isLoggedIn()) {
      refreshData();
      ensureScanEventStream();
    }
  });
  askInventoryButton.addEventListener("click", askInventory);
  inventoryAssistantQuery.addEventListener("keydown", (event) => {
    if (event.key === "Enter") {
      event.preventDefault();
      askInventory();
    }
  });
  databaseResultRows.addEventListener("click", openInventoryRecordFromEvent);
  closeInventoryRecordButton.addEventListener("click", () => inventoryRecordDialog.close());
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
    if (payload.postgresEnabled && (state.databaseConfigDirty || !state.database || !state.database.connected)) {
      const connected = await checkDatabase({silent: true});
      if (!connected) {
        throw new Error("PostgreSQL must be connected before this scan can start.");
      }
    }
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
    replaceScanOutput(state.activeScan);
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
    closeEventSource();
    state.logs = [];
    state.failures = [];
    state.logSequence = 0;
    state.failureSequence = 0;
    state.database = null;
    state.databaseSearch = {query: "", filters: {}, rows: [], total: 0, limit: 100, offset: 0, loaded: false};
    resetDatabaseFacets();
    databaseSearchQuery.value = "";
    resetDatabaseColumnFilters();
    setActiveInventoryFilterButton("all");
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
    state.failures = [];
    renderAll();
    return;
  }
  try {
    const response = await fetch("/api/scans");
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Could not refresh scans.");
    }
    state.scans = (data.scans || []).map(stampScan);
    if (preferredId) {
      const selected = state.scans.find((scan) => scan.id === preferredId);
      if (selected) {
        await selectScan(selected, false);
      }
    } else if (!state.activeScan && state.scans.length) {
      await selectScan(state.scans[0]);
    } else if (state.activeScan) {
      const refreshed = state.scans.find((scan) => scan.id === state.activeScan.id);
      if (refreshed) {
        syncScanOutput(refreshed);
        state.activeScan = refreshed;
        ensureScanEventStream(refreshed);
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
    if (!response.ok) {
      throw new Error(data.error || "Could not open scan.");
    }
    state.activeScan = stampScan(data.scan || scan);
    replaceScanOutput(state.activeScan);
    renderAll();
    if (connect && ["running", "paused"].includes(state.activeScan.status)) {
      ensureScanEventStream(state.activeScan);
    } else if (connect) {
      closeEventSource();
    }
  } catch (error) {
    notify(error.message || "Could not open scan.");
  }
}

function listenToScan(scanId) {
  if (!scanEventStreamNeedsReconnect(scanId)) {
    return;
  }
  closeEventSource();
  const source = new EventSource(`/api/scans/${scanId}/events`);
  state.eventSource = source;
  state.eventSourceScanId = scanId;
  state.eventSourceStartedAt = Date.now();
  source.addEventListener("open", markScanEventReceived);
  source.addEventListener("status", (event) => {
    markScanEventReceived();
    const scan = stampScan(JSON.parse(event.data));
    syncScanOutput(scan);
    state.activeScan = scan;
    mergeScan(state.activeScan);
    renderAll();
  });
  source.addEventListener("log", (event) => {
    markScanEventReceived();
    const data = JSON.parse(event.data);
    if (data.line) {
      const sequence = nonNegativeInteger(data.sequence);
      if (sequence && sequence <= state.logSequence) {
        return;
      }
      state.logs.push(data.line);
      state.logSequence = sequence || state.logSequence + 1;
      if (state.logs.length > 1300) {
        state.logs = state.logs.slice(-1200);
        renderLogs();
      } else {
        appendLogLine(data.line);
      }
      if (data.failure === true || isFailureLogLine(data.line)) {
        state.failures.push(data.line);
        state.failureSequence += 1;
        state.activeScan.failureCount = Number(state.activeScan.failureCount || 0) + 1;
        if (state.failures.length > 1300) {
          state.failures = state.failures.slice(-1200);
          renderFailures();
        } else {
          appendFailureLine(data.line);
        }
      }
      if (/\b(detected|confirmed|match)\b|found \d+ inventory/i.test(data.line)) {
        scheduleDatabaseRefresh();
      }
    }
  });
  source.addEventListener("done", async (event) => {
    markScanEventReceived();
    state.activeScan = stampScan(JSON.parse(event.data));
    mergeScan(state.activeScan);
    closeEventSource();
    await loadScans(state.activeScan.id);
    state.databaseFacets.loaded = false;
    await searchDatabase(0, state.databaseSearch.query, {filters: state.databaseSearch.filters, silent: true});
    notify(`Scan ${state.activeScan.status}.`);
  });
  source.addEventListener("error", () => {
    if (state.eventSource === source && source.readyState === EventSource.CLOSED) {
      closeEventSource();
      loadSession();
    }
  });
}

function ensureScanEventStream(scan = state.activeScan) {
  if (!scan || !["running", "paused"].includes(scan.status)) {
    if (scan && state.eventSourceScanId === scan.id) {
      closeEventSource();
    }
    return;
  }
  listenToScan(scan.id);
}

function scanEventStreamNeedsReconnect(scanId) {
  if (!state.eventSource || state.eventSourceScanId !== scanId) {
    return true;
  }
  if (state.eventSource.readyState === EventSource.CLOSED) {
    return true;
  }
  const lastActivity = Math.max(
    state.eventSourceStartedAt,
    state.eventSourceLastEventAt,
  );
  return state.eventSource.readyState === EventSource.CONNECTING
    && Date.now() - lastActivity >= 10000;
}

function markScanEventReceived() {
  state.eventSourceLastEventAt = Date.now();
}

function closeEventSource() {
  if (state.eventSource) {
    state.eventSource.close();
    state.eventSource = null;
  }
  state.eventSourceScanId = "";
  state.eventSourceStartedAt = 0;
  state.eventSourceLastEventAt = 0;
}

function replaceScanOutput(scan) {
  state.logs = Array.isArray(scan.logsTail) ? scan.logsTail.slice(-1200) : [];
  state.failures = Array.isArray(scan.failuresTail)
    ? scan.failuresTail.slice(-1200)
    : state.logs.filter(isFailureLogLine);
  state.logSequence = nonNegativeInteger(scan.logSequence);
  state.failureSequence = nonNegativeInteger(scan.failureCount);
}

function syncScanOutput(scan) {
  const logSequence = nonNegativeInteger(scan.logSequence);
  if (logSequence > state.logSequence) {
    const tail = Array.isArray(scan.logsTail) ? scan.logsTail : [];
    const missing = Math.min(logSequence - state.logSequence, tail.length);
    state.logs = [...state.logs, ...tail.slice(-missing)].slice(-1200);
    state.logSequence = logSequence;
  }
  const failureSequence = nonNegativeInteger(scan.failureCount);
  if (failureSequence > state.failureSequence) {
    const tail = Array.isArray(scan.failuresTail) ? scan.failuresTail : [];
    const missing = Math.min(failureSequence - state.failureSequence, tail.length);
    state.failures = [...state.failures, ...tail.slice(-missing)].slice(-1200);
    state.failureSequence = failureSequence;
  }
}

function nonNegativeInteger(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0 ? number : 0;
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
  renderLocalLlmStatus();
  renderLogs();
  renderFailures();
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
    downloadFailuresButton.disabled = true;
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
  downloadFailuresButton.disabled = state.failures.length === 0;
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
  const enabled = form.elements.postgresEnabled.checked;
  const database = state.database;
  if (!enabled) {
    databaseReadyBadge.className = "status-chip idle";
    databaseReadyBadge.textContent = "Sync off";
    databaseStatus.className = "database-status";
    databaseStatus.innerHTML = "<strong>Database sync is off</strong><span>Enable sync to test PostgreSQL.</span>";
    return;
  }
  if (!database) {
    databaseReadyBadge.className = "status-chip status-running";
    databaseReadyBadge.textContent = "Checking";
    databaseStatus.className = "database-status";
    databaseStatus.innerHTML = `
      <strong>Checking connection</strong>
      <span>${escapeHtml(form.elements.postgresSchema.value || defaultValues.postgresSchema)}</span>
    `;
    return;
  }
  const connected = Boolean(database.connected);
  databaseReadyBadge.className = `status-chip ${connected ? "status-succeeded" : "status-failed"}`;
  databaseReadyBadge.textContent = connected ? "Ready" : "Unavailable";
  databaseStatus.className = `database-status ${connected ? "connected" : "failed"}`;
  databaseStatus.innerHTML = `
    <strong>${connected ? "Connected" : "Unavailable"}</strong>
    <span>${escapeHtml(database.message || database.status || "")}</span>
    <span>${escapeHtml(database.schema || form.elements.postgresSchema.value || defaultValues.postgresSchema)} · ${escapeHtml(String(database.branchRows ?? 0))} records${database.latencyMs ? ` · ${escapeHtml(String(database.latencyMs))} ms` : ""}</span>
  `;
}

function renderDatabaseResults() {
  const search = state.databaseSearch;
  renderDatabaseSortHeaders(search.filters || {});
  if (!search.loaded) {
    databaseResultSummary.textContent = "Loading inventory records";
    databaseResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="9">Loading inventory records.</td></tr>';
    databasePagePosition.textContent = "Page 1";
    databaseRecordCount.textContent = "Loading records";
    databasePreviousButton.disabled = true;
    databaseNextButton.disabled = true;
    databaseLiveStatus.textContent = state.database && !state.database.connected ? "PostgreSQL is unavailable" : "Loading your inventory";
    return;
  }
  const start = search.total ? search.offset + 1 : 0;
  const end = Math.min(search.offset + search.rows.length, search.total);
  const filterLabel = search.query ? ` matching "${search.query}"` : "";
  databaseResultSummary.textContent = `Showing ${start}-${end} of ${search.total}${filterLabel}`;
  databaseLiveStatus.textContent = scanIsActive()
    ? "Updating as findings are committed"
    : `Updated ${formatTime(search.refreshedAt || Date.now())}`;
  if (!search.rows.length) {
    databaseResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="9">No inventory records match these filters.</td></tr>';
  } else {
    databaseResultRows.innerHTML = search.rows.map((row, index) => `
      <tr>
        <td>${databaseApplicationCell(row, index)}</td>
        <td>${databaseRepositoryCell(row)}</td>
        <td>${databaseCell(row.branch_name)}</td>
        <td>${databaseCell(row.primary_language)}</td>
        <td>${databaseDomainCell(row)}</td>
        <td>${databaseCell(formatDate(row.branch_last_updated || row.last_updated))}</td>
        <td>${confidenceCell(row.confidence)}</td>
        <td>${databaseCell(providerLabel(row.provider))}</td>
        <td>${databaseCell(row.inventory_types)}</td>
      </tr>
    `).join("");
  }
  const page = search.total ? Math.floor(search.offset / search.limit) + 1 : 1;
  const pages = Math.max(1, Math.ceil(search.total / search.limit));
  databasePagePosition.textContent = `Page ${page} of ${pages}`;
  databaseRecordCount.textContent = `${Number(search.total).toLocaleString()} ${search.total === 1 ? "matching record" : "matching records"}`;
  databasePreviousButton.disabled = search.offset <= 0;
  databaseNextButton.disabled = search.offset + search.rows.length >= search.total;
}

function databaseCell(value) {
  const text = String(value ?? "").trim();
  return escapeHtml(text || "Not detected");
}

function databaseApplicationCell(row, index) {
  const name = row.inventory_name || row.mobile_name || row.repo_name || "Not detected";
  const metadata = row.inventory_version || row.mobile_version || "";
  return `
    <button class="inventory-record-link" type="button" data-record-index="${index}">${escapeHtml(name)}</button>
    ${metadata ? `<small class="database-cell-meta">${escapeHtml(metadata)}</small>` : ""}
  `;
}

function databaseRepositoryCell(row) {
  const name = String(row.repo_name || "Not detected").trim();
  const scope = [row.organization, row.project].filter(Boolean).join(" / ");
  const repositoryUrl = safeExternalUrl(row.repository_url);
  const repository = repositoryUrl
    ? `<a class="database-repository-link" href="${escapeHtml(repositoryUrl)}" target="_blank" rel="noopener noreferrer" aria-label="Open ${escapeHtml(name)} repository in a new tab" title="Open repository in a new tab">${escapeHtml(name)}</a>`
    : `<strong class="database-cell-title">${escapeHtml(name)}</strong>`;
  return `${repository}${scope ? `<small class="database-cell-meta">${escapeHtml(scope)}</small>` : ""}`;
}

function safeExternalUrl(value) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  try {
    const url = new URL(text);
    if (!["http:", "https:"].includes(url.protocol)) {
      return "";
    }
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    if (url.pathname.toLowerCase().endsWith(".git")) {
      url.pathname = url.pathname.slice(0, -4);
    }
    return url.href;
  } catch {
    return "";
  }
}

function confidenceCell(value) {
  const confidence = String(value || "unknown").toLowerCase();
  return `<span class="confidence-badge confidence-${escapeHtml(confidence)}">${escapeHtml(capitalize(confidence))}</span>`;
}

function databaseDomainCell(row) {
  const domain = String(row.primary_web_domain || "").trim();
  if (!domain) {
    return '<span class="database-domain-empty">Not detected</span>';
  }
  const status = String(row.web_domain_status || "configured").trim();
  return `<span class="database-domain-value">${escapeHtml(domain)}</span><small class="database-domain-status">${escapeHtml(capitalize(status))}</small>`;
}

function renderLocalLlmStatus() {
  const localLlm = state.localLlm || {};
  const available = Boolean(localLlm.enabled && localLlm.available);
  localLlmStatus.className = `status-chip ${available ? "status-succeeded" : "idle"}`;
  localLlmStatus.textContent = available ? `AI ready · ${localLlm.model || "Local model"}` : localLlm.message || "Local AI offline";
  askInventoryButton.disabled = !available;
  inventoryAssistantQuery.disabled = !available;
}

function openInventoryRecordFromEvent(event) {
  const button = event.target.closest("[data-record-index]");
  if (!button) {
    return;
  }
  const row = state.databaseSearch.rows[Number(button.dataset.recordIndex)];
  if (!row) {
    return;
  }
  const isMobileApp = inventoryRecordHasType(row, "mobile_app");
  inventoryRecordTitle.textContent = row.inventory_name || row.mobile_name || row.repo_name || "Application details";
  const fields = [
    {label: "Source", value: providerLabel(row.provider)},
    {label: "Organization", value: row.organization},
    {label: "Project", value: row.project},
    {label: "Repository", value: row.repo_name},
    {label: "Branch", value: row.branch_name},
    {label: "Application version", value: row.inventory_version || row.mobile_version},
    {label: "Application types", value: row.inventory_types},
    {label: "Language", value: row.primary_language},
    {label: "Web domains", value: row.web_domains},
    {label: "Domain status", value: row.web_domain_status},
    {label: "Contributors", value: row.branch_contributing_developers},
    {label: "Last updated", value: formatDate(row.branch_last_updated || row.last_updated)},
    {label: "Confidence", value: row.confidence},
    ...(isMobileApp ? [
      {label: "Mobile identifier", value: row.mobile_identifier},
      {label: "Store platforms", value: row.store_platforms},
      {label: "Store validation", value: storeValidationDetailValue(row)},
    ] : []),
    {label: "Semgrep target", value: row.semgrep_target, target: true},
    {label: "SonarQube key", value: row.sonarqube_project_key, target: true},
    ...(isMobileApp ? [
      {label: "NowSecure target", value: row.nowsecure_target || row.scanner_target || row.semgrep_target, target: true},
    ] : []),
  ].filter(({value}) => String(value ?? "").trim());
  inventoryRecordDetails.innerHTML = fields.map(({label, value, target}) => `
    <div${target ? ' class="inventory-detail-target"' : ""}><dt>${escapeHtml(label)}</dt><dd>${escapeHtml(value)}</dd></div>
  `).join("");
  inventoryRecordDialog.showModal();
}

function inventoryRecordHasType(row, applicationType) {
  const rawTypes = Array.isArray(row.inventory_types)
    ? row.inventory_types
    : String(row.inventory_types || "").split(/[;,]/);
  return rawTypes.some((value) => String(value).trim().toLowerCase() === applicationType);
}

function storeValidationDetailValue(row) {
  const status = String(row.store_lookup_status || "").trim().toLowerCase();
  if (!status || ["disabled", "not_requested"].includes(status)) {
    return "";
  }
  if (status === "identifier_missing") {
    return "Not run: mobile identifier missing";
  }
  if (status === "identifier_invalid") {
    return "Not run: mobile identifier invalid";
  }
  if (status === "error") {
    return "Error";
  }
  if (row.store_validation_passed == null) {
    return "";
  }
  return row.store_validation_passed ? "Passed" : "Failed";
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

function renderFailures() {
  const fragment = document.createDocumentFragment();
  state.failures.forEach((line, index) => {
    if (index > 0) {
      fragment.append(document.createTextNode("\n"));
    }
    const element = document.createElement("span");
    element.className = "log-error";
    element.textContent = line;
    fragment.append(element);
  });
  failuresElement.replaceChildren(fragment);
  failuresElement.scrollTop = failuresElement.scrollHeight;
  failureCount.textContent = String(state.activeScan ? state.activeScan.failureCount || 0 : 0);
  downloadFailuresButton.disabled = state.failures.length === 0;
}

function appendFailureLine(line) {
  if (failuresElement.childNodes.length) {
    failuresElement.append(document.createTextNode("\n"));
  }
  const element = document.createElement("span");
  element.className = "log-error";
  element.textContent = line;
  failuresElement.append(element);
  failuresElement.scrollTop = failuresElement.scrollHeight;
  failureCount.textContent = String(state.activeScan ? state.activeScan.failureCount || 0 : state.failures.length);
  downloadFailuresButton.disabled = false;
}

function isFailureLogLine(line) {
  const value = String(line || "").trim().replace(/\b(?:no|zero|0)\s+(?:errors?|failures?)\b|\b(?:errors?|failures?)\s*[:=]\s*0\b/gi, "");
  if (isConfirmedFindingLine(value)) {
    return false;
  }
  return /\b(?:critical|errors?|failed|failures?|fatal|exception|traceback)\b|\bcould not\b|\bunable to\b|\bmissing\b.+\bconfiguration\b|\b(?:http|status)(?:\s+status)?[\s:=]+[45]\d{2}\b/i.test(value);
}

function isConfirmedFindingLine(line) {
  return /\bDETECTED\s+(?:asset|app)=|\bfound\s+\d+\s+inventory\b/i.test(String(line || ""));
}

function logTone(line) {
  const value = String(line || "").toLowerCase();
  if (isConfirmedFindingLine(value)) {
    return "log-success";
  }
  if (isFailureLogLine(value)) {
    return "log-error";
  }
  if (/\b(detected|confirmed|match)\b|found \d+ inventory/.test(value)) {
    return "log-success";
  }
  return "";
}

async function initializeDatabase() {
  renderDatabaseStatus();
  renderLocalLlmStatus();
  if (!form.elements.postgresEnabled.checked) {
    return;
  }
  const connected = await checkDatabase({silent: true});
  if (connected) {
    await searchDatabase(0, "", {filters: {}, silent: true});
  }
}

async function checkDatabase({silent = false} = {}) {
  if (!silent) {
    setDatabaseBusy(true);
  }
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
    state.databaseConfigDirty = false;
    renderDatabaseStatus();
    if (!silent) {
      notify(data.database && data.database.connected ? "Database connected." : "Database unavailable.");
    }
    return Boolean(data.database && data.database.connected);
  } catch (error) {
    state.database = {connected: false, message: error.message || "Database check failed."};
    renderDatabaseStatus();
    if (!silent) {
      notify(error.message || "Database check failed.");
    }
    return false;
  } finally {
    if (!silent) {
      setDatabaseBusy(false);
    }
  }
}

async function searchDatabase(offset = 0, query = "", {filters = state.databaseSearch.filters || {}, silent = false} = {}) {
  if (state.databaseSearchBusy) {
    return false;
  }
  state.databaseSearchBusy = true;
  if (!silent) {
    setDatabaseBusy(true);
  }
  try {
    const response = await fetch("/api/database/search", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({
        ...databasePayload(),
        query,
        filters,
        offset,
        limit: state.databaseSearch.limit,
        includeFacets: !state.databaseFacets.loaded,
      }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Database search failed.");
    }
    if (data.search.facets) {
      state.databaseFacets = {
        languages: Array.isArray(data.search.facets.languages) ? data.search.facets.languages : [],
        loaded: true,
      };
      renderDatabaseLanguageOptions(selectedDatabaseLanguages());
    }
    state.databaseSearch = {...data.search, loaded: true, refreshedAt: Date.now()};
    databaseSearchQuery.value = data.search.query || "";
    renderDatabaseResults();
    return true;
  } catch (error) {
    databaseLiveStatus.textContent = error.message || "Database search failed";
    if (!silent) {
      notify(error.message || "Database search failed.");
    }
    return false;
  } finally {
    state.databaseSearchBusy = false;
    if (!silent) {
      setDatabaseBusy(false);
    }
  }
}

async function exportDatabase(format) {
  setDatabaseBusy(true);
  try {
    const response = await fetch("/api/database/export", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({
        ...databasePayload(),
        format,
        query: state.databaseSearch.query,
        filters: state.databaseSearch.filters || {},
      }),
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

async function askInventory() {
  const question = inventoryAssistantQuery.value.trim();
  if (!question) {
    inventoryAssistantQuery.focus();
    return;
  }
  askInventoryButton.disabled = true;
  inventoryAssistantSummary.textContent = "AI is interpreting your request";
  try {
    const response = await fetch("/api/database/interpret", {
      method: "POST",
      headers: authHeaders(true),
      body: JSON.stringify({question}),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "The local model could not interpret that request.");
    }
    const plan = data.plan || {};
    const filters = plan.filters || {};
    const query = filters.text || "";
    databaseSearchQuery.value = query;
    inventoryAssistantSummary.textContent = plan.summary || "Query ready";
    setActiveInventoryFilterButton("");
    populateDatabaseColumnFilters(filters);
    await searchDatabase(0, query, {filters});
    if (plan.action === "export") {
      await exportDatabase(plan.exportFormat || "xlsx");
    }
  } catch (error) {
    inventoryAssistantSummary.textContent = error.message || "The local model could not interpret that request.";
    notify(inventoryAssistantSummary.textContent);
  } finally {
    renderLocalLlmStatus();
  }
}

function activateInventoryFilter(name) {
  resetDatabaseColumnFilters();
  const current = state.databaseSearch.filters || {};
  const filters = {
    ...inventoryFilterCriteria(name),
    sort_by: current.sort_by || "updated",
    sort_direction: current.sort_direction || "desc",
  };
  setActiveInventoryFilterButton(name);
  inventoryAssistantSummary.textContent = "";
  searchDatabase(0, databaseSearchQuery.value, {filters});
}

function inventoryFilterCriteria(name) {
  const filters = {
    active: {updated_within_days: 90},
    older: {older_than_days: 90},
    "has-domain": {has_domain: true},
    "missing-domain": {has_domain: false},
    "mobile-app": {application_types: ["mobile_app"]},
    "web-app": {application_types: ["web_app"]},
    "api-service": {application_types: ["api_service"]},
    microservice: {application_types: ["microservice"]},
    middleware: {application_types: ["middleware"]},
    serverless: {application_types: ["serverless"]},
    library: {application_types: ["library"]},
    infrastructure: {application_types: ["infrastructure"]},
    "ai-enabled": {application_types: ["ai_enabled"]},
    "ml-enabled": {application_types: ["ml_enabled"]},
  };
  return filters[name] || {};
}

function sortDatabase(column) {
  const filters = {...(state.databaseSearch.filters || {})};
  const currentColumn = filters.sort_by || "updated";
  const defaultDirection = ["updated", "confidence"].includes(column) ? "desc" : "asc";
  filters.sort_by = column;
  filters.sort_direction = currentColumn === column
    ? (filters.sort_direction === "asc" ? "desc" : "asc")
    : defaultDirection;
  searchDatabase(0, state.databaseSearch.query, {filters});
}

function renderDatabaseSortHeaders(filters) {
  const column = filters.sort_by || "updated";
  const direction = filters.sort_direction || "desc";
  databaseSortButtons.forEach((button) => {
    const active = button.dataset.databaseSort === column;
    const header = button.closest("th");
    button.classList.toggle("active", active);
    button.querySelector(".sort-indicator").textContent = active ? (direction === "asc" ? "↑" : "↓") : "↕";
    header.setAttribute("aria-sort", active ? (direction === "asc" ? "ascending" : "descending") : "none");
  });
}

function scheduleColumnFilterSearch(event) {
  event.stopPropagation();
  setActiveInventoryFilterButton("");
  state.databaseSearch.filters = databaseFiltersFromControls();
  window.clearTimeout(scheduleColumnFilterSearch.timeout);
  if (event.currentTarget.matches("select")) {
    applyDatabaseColumnFilters();
    return;
  }
  scheduleColumnFilterSearch.timeout = window.setTimeout(applyDatabaseColumnFilters, 350);
}

function applyDatabaseColumnFilters() {
  window.clearTimeout(scheduleColumnFilterSearch.timeout);
  const filters = databaseFiltersFromControls();
  state.databaseSearch.filters = filters;
  searchDatabase(0, databaseSearchQuery.value, {filters});
}

function databaseFiltersFromControls() {
  const filters = {...(state.databaseSearch.filters || {})};
  for (const key of [
    "application_search",
    "repository_search",
    "branch_search",
    "has_domain",
    "updated_within_days",
    "older_than_days",
    "confidences",
    "providers",
    "application_types",
    "languages",
  ]) {
    delete filters[key];
  }
  Object.assign(filters, databaseColumnFilterCriteria());
  return filters;
}

function databaseColumnFilterCriteria() {
  const filters = {};
  const application = databaseColumnFilters.application.value.trim();
  const repository = databaseColumnFilters.repository.value.trim();
  const branch = databaseColumnFilters.branch.value.trim();
  if (application) {
    filters.application_search = application;
  }
  if (repository) {
    filters.repository_search = repository;
  }
  if (branch) {
    filters.branch_search = branch;
  }
  if (databaseColumnFilters.domain.value) {
    filters.has_domain = databaseColumnFilters.domain.value === "has";
  }
  if (databaseColumnFilters.updated.value === "active") {
    filters.updated_within_days = 90;
  } else if (databaseColumnFilters.updated.value === "older") {
    filters.older_than_days = 90;
  }
  if (databaseColumnFilters.confidence.value) {
    filters.confidences = [databaseColumnFilters.confidence.value];
  }
  if (databaseColumnFilters.source.value) {
    filters.providers = [databaseColumnFilters.source.value];
  }
  const applicationTypes = selectedDatabaseTypes();
  if (applicationTypes.length) {
    filters.application_types = applicationTypes;
  }
  const languages = selectedDatabaseLanguages();
  if (languages.length) {
    filters.languages = languages;
  }
  return filters;
}

function populateDatabaseColumnFilters(filters = {}) {
  databaseColumnFilters.application.value = filters.application_search || "";
  databaseColumnFilters.repository.value = filters.repository_search || "";
  databaseColumnFilters.branch.value = filters.branch_search || "";
  databaseColumnFilters.domain.value = filters.has_domain === true ? "has" : filters.has_domain === false ? "missing" : "";
  databaseColumnFilters.updated.value = filters.updated_within_days ? "active" : filters.older_than_days ? "older" : "";
  databaseColumnFilters.confidence.value = filters.confidences && filters.confidences.length === 1 ? filters.confidences[0] : "";
  databaseColumnFilters.source.value = filters.providers && filters.providers.length === 1 ? filters.providers[0] : "";
  setDatabaseTypeFilters(filters.application_types || []);
  setDatabaseLanguageFilters(filters.languages || []);
}

function resetDatabaseColumnFilters() {
  Object.values(databaseColumnFilters).forEach((control) => {
    control.value = "";
  });
  setDatabaseTypeFilters([]);
  setDatabaseLanguageFilters([]);
}

function selectedDatabaseTypes() {
  return databaseTypeCheckboxes
    .filter((checkbox) => checkbox.checked)
    .map((checkbox) => checkbox.value);
}

function setDatabaseTypeFilters(values) {
  const selected = new Set(Array.isArray(values) ? values : []);
  databaseTypeCheckboxes.forEach((checkbox) => {
    checkbox.checked = selected.has(checkbox.value);
  });
  renderDatabaseTypeFilter();
}

function renderDatabaseTypeFilter() {
  const selected = selectedDatabaseTypes();
  const labels = selected.map(applicationTypeLabel);
  databaseTypeFilterSummary.textContent = labels.length === 0
    ? "Any type"
    : labels.length === 1
      ? labels[0]
      : `${labels.length} types selected`;
  databaseTypeFilterSummary.title = labels.length ? labels.join(", ") : "All application types";
  databaseTypeFilterSummary.setAttribute(
    "aria-label",
    labels.length
      ? `Filter application types. Selected: ${labels.join(", ")}`
      : "Filter application types. All types",
  );
  databaseTypeFilter.classList.toggle("active", selected.length > 0);
  clearDatabaseTypeFilterButton.disabled = selected.length === 0;
}

function databaseLanguageCheckboxes() {
  return Array.from(databaseLanguageOptions.querySelectorAll('input[name="databaseFilterLanguage"]'));
}

function selectedDatabaseLanguages() {
  return databaseLanguageCheckboxes()
    .filter((checkbox) => checkbox.checked)
    .map((checkbox) => checkbox.value);
}

function setDatabaseLanguageFilters(values) {
  renderDatabaseLanguageOptions(Array.isArray(values) ? values : []);
}

function renderDatabaseLanguageOptions(selectedValues = selectedDatabaseLanguages()) {
  const selected = selectedValues.map((value) => String(value || "").trim()).filter(Boolean);
  const selectedKeys = new Set(selected.map((value) => value.toLocaleLowerCase()));
  const languagesByKey = new Map();
  [...(state.databaseFacets.languages || []), ...selected].forEach((value) => {
    const language = String(value || "").trim();
    const key = language.toLocaleLowerCase();
    if (language && !languagesByKey.has(key)) {
      languagesByKey.set(key, language);
    }
  });
  const languages = Array.from(languagesByKey.values())
    .sort((left, right) => left.localeCompare(right, undefined, {sensitivity: "base"}));
  databaseLanguageOptions.innerHTML = languages.map((language) => `
    <label class="database-type-option">
      <input name="databaseFilterLanguage" type="checkbox" value="${escapeHtml(language)}"${selectedKeys.has(language.toLocaleLowerCase()) ? " checked" : ""}>
      <span>${escapeHtml(language)}</span>
    </label>
  `).join("");
  databaseLanguageEmpty.hidden = languages.length > 0;
  databaseLanguageCheckboxes().forEach((checkbox) => {
    checkbox.disabled = state.databaseSearchBusy;
  });
  renderDatabaseLanguageFilterSummary();
}

function renderDatabaseLanguageFilterSummary() {
  const selected = selectedDatabaseLanguages();
  databaseLanguageFilterSummary.textContent = selected.length === 0
    ? "Any language"
    : selected.length === 1
      ? selected[0]
      : `${selected.length} languages selected`;
  databaseLanguageFilterSummary.title = selected.length ? selected.join(", ") : "All languages";
  databaseLanguageFilterSummary.setAttribute(
    "aria-label",
    selected.length
      ? `Filter languages. Selected: ${selected.join(", ")}`
      : "Filter languages. All languages",
  );
  databaseLanguageFilter.classList.toggle("active", selected.length > 0);
  clearDatabaseLanguageFilterButton.disabled = selected.length === 0 || state.databaseSearchBusy;
}

function resetDatabaseFacets() {
  state.databaseFacets = {languages: [], loaded: false};
  setDatabaseLanguageFilters([]);
}

function setActiveInventoryFilterButton(name) {
  inventoryFilterButtons.forEach((button) => {
    button.classList.toggle("active", button.dataset.inventoryFilter === name);
  });
}

function scheduleDatabaseRefresh() {
  if (!state.databaseSearch.loaded || !form.elements.postgresEnabled.checked) {
    return;
  }
  window.clearTimeout(state.databaseRefreshTimer);
  state.databaseRefreshTimer = window.setTimeout(() => {
    searchDatabase(0, state.databaseSearch.query, {filters: state.databaseSearch.filters, silent: true});
  }, 800);
}

function scheduleDatabaseConnectionCheck() {
  if (!isLoggedIn() || !form.elements.postgresEnabled.checked) {
    return;
  }
  window.clearTimeout(scheduleDatabaseConnectionCheck.timeout);
  scheduleDatabaseConnectionCheck.timeout = window.setTimeout(() => checkDatabase({silent: true}), 700);
}

function databaseFieldChanged(target) {
  return Boolean(target && target.name && target.name.startsWith("postgres"));
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

function downloadFailures() {
  if (!state.failures.length) {
    return;
  }
  const report = state.activeScan && (state.activeScan.reports || []).find((item) => item.name === "failures.log");
  if (state.activeScan) {
    const link = document.createElement("a");
    link.href = report ? report.url : `/api/scans/${encodeURIComponent(state.activeScan.id)}/reports/failures.log`;
    link.click();
    return;
  }
  const blob = new Blob([state.failures.join("\n")], {type: "text/plain"});
  downloadBlob(blob, `${state.activeScan ? state.activeScan.id : "scan"}-failures.log`);
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
  exportDatabaseXlsxButton.disabled = isBusy;
  exportDatabaseCsvButton.disabled = isBusy;
  exportDatabaseJsonButton.disabled = isBusy;
  inventoryFilterButtons.forEach((button) => {
    button.disabled = isBusy;
  });
  databaseSortButtons.forEach((button) => {
    button.disabled = isBusy;
  });
  Object.values(databaseColumnFilters).forEach((control) => {
    control.disabled = isBusy;
  });
  databaseTypeCheckboxes.forEach((checkbox) => {
    checkbox.disabled = isBusy;
  });
  databaseLanguageCheckboxes().forEach((checkbox) => {
    checkbox.disabled = isBusy;
  });
  clearDatabaseTypeFilterButton.disabled = isBusy || selectedDatabaseTypes().length === 0;
  clearDatabaseLanguageFilterButton.disabled = isBusy || selectedDatabaseLanguages().length === 0;
  if (isBusy) {
    askInventoryButton.disabled = true;
  } else {
    renderLocalLlmStatus();
  }
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
  if (scanIsActive()) {
    ensureScanEventStream();
  }
  state.pollTicks += 1;
  if (state.pollTicks % 2 === 0 && scanIsActive()) {
    scheduleDatabaseRefresh();
  }
  if (state.pollTicks >= 30 && !document.hidden) {
    state.pollTicks = 0;
    refreshData();
  }
}

function scanIsActive() {
  return Boolean(state.activeScan && ["running", "paused"].includes(state.activeScan.status));
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

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "just now" : date.toLocaleTimeString([], {hour: "numeric", minute: "2-digit", second: "2-digit"});
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
