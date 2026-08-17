import {riskDistributionMarkup} from "/static/aspm/posture.js?v=4";

export class AspmWorkspace {
  constructor(dependencies) {
    this.databasePayload = dependencies.databasePayload;
    this.authHeaders = dependencies.authHeaders;
    this.notify = dependencies.notify;
    this.escapeHtml = dependencies.escapeHtml;
    this.formatDate = dependencies.formatDate;
    this.downloadBlob = dependencies.downloadBlob;
    this.setActiveView = dependencies.setActiveView;
    this.openAffectedInventory = dependencies.openAffectedInventory;
    this.state = {
      posture: null,
      findingRequest: 0,
      findings: {rows: [], total: null, limit: 25, offset: 0, facets: {}, hasMore: false, nextCursor: null, loaded: false},
      findingCursors: [null],
      coverage: {rows: [], total: 0, limit: 100, offset: 0, summary: {}, loaded: false, requestId: 0},
      assetRisks: {rows: [], total: 0, limit: 25, offset: 0, activeOnly: false, loaded: false, assetRiskRequest: 0},
      connectors: {items: [], syncs: [], loaded: false},
      findingFilters: {},
      findingDrilldownFilters: {},
      quickFilter: "active",
      activeFinding: null,
      activeAsset: null,
      busy: new Set(),
      refreshedAt: {},
    };
    this.elements = {};
  }

  bind() {
    this.elements = Object.fromEntries(
      [
        "postureStatus", "postureCritical", "postureHigh",
        "postureAffectedAssets", "postureAssetContext", "postureOverdue",
        "postureCoverage", "postureAverageRisk", "riskDistribution",
        "statusDistribution", "priorityAssetList", "toolHealthGrid",
        "refreshConnectors", "testConnectors", "syncConnectors", "connectorGrid", "connectorSyncSummary",
        "connectorSetupDialog", "connectorSetupType", "connectorSetupTitle",
        "connectorSetupDescription", "connectorSetupKey", "connectorSetupFields",
        "connectorSetupStatus", "closeConnectorSetup", "saveConnectorSetup",
        "connectorLogsDialog", "connectorLogsTitle", "connectorLogsEyebrow",
        "connectorLogsBody", "closeConnectorLogs",
        "viewAllFindings", "openFindingImport", "toggleFindingImport",
        "findingImportPanel", "closeFindingImport", "findingImportFormat",
        "findingImportTool", "findingImportFile", "findingCompleteSnapshot",
        "findingContextProvider", "findingContextOrganization",
        "findingContextProject", "findingContextRepository", "findingContextBranch",
        "findingImportStatus", "submitFindingImport", "findingSearchQuery",
        "findingSeverityFilter", "findingStatusFilter", "findingToolFilter",
        "searchFindings", "clearFindingFilters", "findingResultSummary",
        "findingResultRows", "findingPrevious", "findingNext",
        "findingPageSize", "findingPagePosition", "findingRecordCount", "findingDialog",
        "findingDialogTitle", "closeFindingDialog", "findingDetailSummary",
        "findingWorkflowStatus", "findingWorkflowAssignee", "findingWorkflowDue",
        "findingWorkflowNote", "findingWorkflowMessage", "saveFindingWorkflow",
        "findingHistory", "refreshCoverage", "coverageCurrent", "coverageStale",
        "coverageUntested", "coveragePercent", "coverageResultSummary",
        "coverageResultRows", "coveragePrevious", "coverageNext",
        "coveragePagePosition", "coverageRecordCount",
        "refreshAssetRisks", "assetRiskQuery", "assetRiskBand",
        "assetRiskDataType", "searchAssetRisks", "clearAssetRisks",
        "assetRiskSummary", "assetRiskRows", "assetRiskPrevious",
        "assetRiskNext", "assetRiskPageSize", "assetRiskPagePosition", "assetRiskRecordCount",
        "assetProfile", "assetProfileStatus", "assetCriticality",
        "assetInternetExposure", "assetDataClassification", "assetBusinessOwner",
        "assetTechnicalOwner", "assetSecurityTags", "assetProfileMessage",
        "saveAssetProfile", "assetProfileRisk",
      ].map((id) => [id, document.querySelector(`#${id}`)])
    );
    if (!this.elements.postureStatus) {
      return;
    }
    document.querySelectorAll("[data-dashboard-action]").forEach((button) => {
      button.addEventListener("click", () => this.openDashboardAction(button.dataset.dashboardAction));
    });
    this.elements.riskDistribution.addEventListener("pointerover", (event) => this.showRiskDistributionTooltip(event));
    this.elements.riskDistribution.addEventListener("focusin", (event) => this.showRiskDistributionTooltip(event));
    this.elements.riskDistribution.addEventListener("pointerout", () => this.hideRiskDistributionTooltip());
    this.elements.riskDistribution.addEventListener("focusout", () => this.hideRiskDistributionTooltip());
    this.elements.toolHealthGrid.addEventListener("click", (event) => {
      if (event.target.closest("[data-tool-health-action='configuration']")) {
        this.setActiveView("databaseView");
        this.loadConnectors(true);
      }
      const logsBtn = event.target.closest("[data-tool-health-action='logs']");
      if (logsBtn) {
        this.openConnectorLogs(logsBtn.dataset.toolKey, logsBtn.dataset.toolName);
      }
    });
    this.elements.priorityAssetList.addEventListener("click", (event) => {
      const item = event.target.closest("[data-priority-asset]");
      if (item) {
        this.openPriorityApplicationFindings(item.dataset.priorityAsset);
      }
    });
    this.elements.statusDistribution.addEventListener("click", (event) => {
      const item = event.target.closest("[data-finding-status]");
      if (item) {
        this.openStatusFindings(item.dataset.findingStatus);
      }
    });
    this.elements.viewAllFindings.addEventListener("click", () => this.openFindings());
    this.elements.openFindingImport.addEventListener("click", () => this.openFindings(true));
    this.elements.toggleFindingImport.addEventListener("click", () => this.toggleImport(true));
    this.elements.closeFindingImport.addEventListener("click", () => this.toggleImport(false));
    this.elements.findingImportFile.addEventListener("change", () => this.fileSelected());
    this.elements.submitFindingImport.addEventListener("click", () => this.importFindings());
    this.elements.searchFindings.addEventListener("click", () => this.searchFindings(0));
    this.elements.clearFindingFilters.addEventListener("click", () => this.clearFindingFilters());
    this.elements.findingSearchQuery.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        this.searchFindings(0);
      }
    });
    [this.elements.findingSeverityFilter, this.elements.findingStatusFilter, this.elements.findingToolFilter]
      .forEach((control) => control.addEventListener("change", () => this.searchFindings(0)));
    document.querySelectorAll("[data-finding-quick-filter]").forEach((button) => {
      button.addEventListener("click", () => this.activateQuickFilter(button.dataset.findingQuickFilter));
    });
    document.querySelectorAll("[data-finding-export]").forEach((button) => {
      button.addEventListener("click", () => this.exportFindings(button.dataset.findingExport));
    });
    this.elements.findingPageSize.addEventListener("change", () => {
      const limit = Number.parseInt(this.elements.findingPageSize.value, 10);
      if (![25, 50, 100].includes(limit)) {
        this.elements.findingPageSize.value = String(this.state.findings.limit);
        return;
      }
      this.state.findings.limit = limit;
      this.searchFindings(0);
    });
    this.elements.findingPrevious.addEventListener("click", () => this.previousFindingsPage());
    this.elements.findingNext.addEventListener("click", () => this.nextFindingsPage());
    this.elements.findingResultRows.addEventListener("click", (event) => this.openFindingFromEvent(event));
    this.elements.findingResultRows.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        this.openFindingFromEvent(event);
      }
    });
    this.elements.closeFindingDialog.addEventListener("click", () => this.elements.findingDialog.close());
    this.elements.saveFindingWorkflow.addEventListener("click", () => this.saveFindingWorkflow());
    this.elements.refreshCoverage.addEventListener("click", () => this.loadCoverage(0, true));
    this.elements.refreshConnectors.addEventListener("click", () => this.loadConnectors(true));
    this.elements.testConnectors.addEventListener("click", () => this.testConnections());
    this.elements.syncConnectors.addEventListener("click", () => this.syncConnectors());
    this.elements.connectorGrid.addEventListener("click", (event) => {
      const button = event.target.closest("[data-connector-setup]");
      if (button) {
        this.openConnectorSetup(button.dataset.connectorSetup);
      }
    });
    this.elements.closeConnectorSetup.addEventListener("click", () => this.elements.connectorSetupDialog.close());
    this.elements.closeConnectorLogs.addEventListener("click", () => this.elements.connectorLogsDialog.close());
    this.elements.saveConnectorSetup.addEventListener("click", () => this.saveConnectorSetup());
    this.elements.refreshAssetRisks.addEventListener("click", () => this.loadAssetRisks(this.state.assetRisks.offset, true));
    this.elements.searchAssetRisks.addEventListener("click", () => this.loadAssetRisks(0, true));
    this.elements.clearAssetRisks.addEventListener("click", () => this.clearAssetRiskFilters());
    this.elements.assetRiskQuery.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        this.loadAssetRisks(0, true);
      }
    });
    [this.elements.assetRiskBand, this.elements.assetRiskDataType]
      .forEach((control) => control.addEventListener("change", () => this.loadAssetRisks(0, true)));
    this.elements.assetRiskPageSize.addEventListener("change", () => {
      const limit = Number.parseInt(this.elements.assetRiskPageSize.value, 10);
      if (![25, 50, 100].includes(limit)) {
        this.elements.assetRiskPageSize.value = String(this.state.assetRisks.limit);
        return;
      }
      this.state.assetRisks.limit = limit;
      this.loadAssetRisks(0, true);
    });
    this.elements.assetRiskPrevious.addEventListener("click", () => {
      this.loadAssetRisks(Math.max(0, this.state.assetRisks.offset - this.state.assetRisks.limit));
    });
    this.elements.assetRiskNext.addEventListener("click", () => {
      this.loadAssetRisks(this.state.assetRisks.offset + this.state.assetRisks.limit);
    });
    this.elements.coveragePrevious.addEventListener("click", () => {
      this.loadCoverage(Math.max(0, this.state.coverage.offset - this.state.coverage.limit));
    });
    this.elements.coverageNext.addEventListener("click", () => {
      this.loadCoverage(this.state.coverage.offset + this.state.coverage.limit);
    });
    this.elements.saveAssetProfile.addEventListener("click", () => this.saveAssetProfile());
  }

  async initialize() {
    await Promise.all([this.loadPosture(), this.searchFindings(0), this.loadCoverage(0), this.loadConnectors()]);
  }

  reset() {
    this.state.posture = null;
    this.state.findingRequest = 0;
    this.state.findings = {rows: [], total: null, limit: 25, offset: 0, facets: {}, hasMore: false, nextCursor: null, loaded: false};
    this.state.findingCursors = [null];
    this.state.coverage = {rows: [], total: 0, limit: 100, offset: 0, summary: {}, loaded: false, requestId: 0};
    this.state.assetRisks = {rows: [], total: 0, limit: 25, offset: 0, activeOnly: false, loaded: false, assetRiskRequest: 0};
    this.state.connectors = {items: [], syncs: [], loaded: false};
    this.state.findingDrilldownFilters = {};
    this.state.activeFinding = null;
    this.state.activeAsset = null;
    this.renderPosture();
    this.renderFindings();
    this.renderCoverage();
    this.renderAssetRisks();
    this.renderConnectors();
  }

  onViewActivated(viewId) {
    const stale = (key) => Date.now() - Number(this.state.refreshedAt[key] || 0) > 30000;
    if (viewId === "dashboardView" && stale("posture")) {
      this.loadPosture();
    } else if (viewId === "findingsView" && stale("findings")) {
      this.searchFindings(this.state.findings.offset);
    } else if (viewId === "coverageView" && stale("coverage")) {
      this.loadCoverage(this.state.coverage.offset);
    } else if (viewId === "riskProfilesView" && stale("assetRisks")) {
      this.loadAssetRisks(this.state.assetRisks.offset);
    } else if (viewId === "databaseView" && stale("connectors")) {
      this.loadConnectors();
    }
  }

  async refreshVisible() {
    const active = document.querySelector(".tab-view.active");
    this.onViewActivated(active ? active.id : "dashboardView");
  }

  async loadPosture(force = false) {
    if (!force && this.state.busy.has("posture")) {
      return;
    }
    this.setBusy("posture", true);
    this.elements.postureStatus.textContent = "Refreshing";
    this.elements.postureStatus.className = "status-chip status-running";
    try {
      const data = await this.postJson("/api/aspm/posture", this.databasePayload());
      this.state.posture = data.posture;
      this.state.refreshedAt.posture = Date.now();
      this.elements.postureStatus.textContent = "Current";
      this.elements.postureStatus.className = "status-chip status-succeeded";
      this.renderPosture();
    } catch (error) {
      this.elements.postureStatus.textContent = "Unavailable";
      this.elements.postureStatus.className = "status-chip status-failed";
      this.notify(error.message || "Security posture could not be loaded.");
    } finally {
      this.setBusy("posture", false);
    }
  }

  renderPosture() {
    if (!this.elements.postureCritical) {
      return;
    }
    const posture = this.state.posture || {};
    const summary = posture.summary || {};
    const coverage = posture.coverage || {};
    this.elements.postureCritical.textContent = this.number(summary.critical_findings);
    this.elements.postureHigh.textContent = this.number(summary.high_findings);
    this.elements.postureAffectedAssets.textContent = this.number(summary.affected_assets);
    this.elements.postureAssetContext.textContent = `of ${this.number(summary.assets)} inventoried`;
    this.elements.postureOverdue.textContent = this.number(summary.overdue_findings);
    this.elements.postureCoverage.textContent = `${Number(coverage.coverage_percent || 0).toLocaleString()}%`;
    this.elements.postureAverageRisk.textContent = this.number(summary.average_risk);
    this.renderRiskDistribution(posture.breakdowns && posture.breakdowns.severity || []);
    this.renderStatusDistribution(posture.breakdowns && posture.breakdowns.status || []);
    this.renderPriorityAssets(posture.topAssets || []);
    this.renderToolHealth(posture.tools || []);
  }

  renderRiskDistribution(items) {
    this.elements.riskDistribution.innerHTML = riskDistributionMarkup(
      items,
      (value) => this.number(value),
      (value) => this.readable(value),
    );
  }

  showRiskDistributionTooltip(event) {
    const segment = event.target.closest("[data-risk-severity]");
    if (!segment) {
      return;
    }
    this.elements.riskDistribution.querySelectorAll(".risk-pie-segment.active")
      .forEach((item) => item.classList.remove("active"));
    segment.classList.add("active");
    const tooltip = this.elements.riskDistribution.querySelector("#riskDistributionTooltip");
    if (!tooltip) {
      return;
    }
    tooltip.hidden = false;
    tooltip.textContent = `${segment.dataset.riskSeverity}: ${this.number(segment.dataset.riskCount)} findings (${segment.dataset.riskPercent}%)`;
  }

  hideRiskDistributionTooltip() {
    const tooltip = this.elements.riskDistribution.querySelector("#riskDistributionTooltip");
    if (tooltip) {
      tooltip.hidden = true;
    }
    this.elements.riskDistribution.querySelectorAll(".risk-pie-segment.active")
      .forEach((item) => item.classList.remove("active"));
  }

  openDashboardAction(action) {
    if (action === "affected-assets") {
      this.openAffectedInventory();
      return;
    }
    if (action === "coverage") {
      this.setActiveView("coverageView");
      return;
    }
    if (action === "average-risk") {
      this.state.assetRisks.activeOnly = true;
      this.loadAssetRisks(0, true);
      this.setActiveView("riskProfilesView");
      return;
    }
    this.setActiveView("findingsView");
    if (action === "overdue") {
      this.elements.findingSeverityFilter.value = "";
      this.activateQuickFilter("overdue");
      return;
    }
    if (action === "critical" || action === "high") {
      this.elements.findingSeverityFilter.value = action;
      this.activateQuickFilter("active");
    }
  }

  renderStatusDistribution(items) {
    this.elements.statusDistribution.innerHTML = items.length
      ? items.slice(0, 6).map((item) => `<button type="button" data-finding-status="${this.escapeHtml(item.name)}"><span>${this.readable(item.name)}</span><strong>${this.number(item.count)}</strong></button>`).join("")
      : "";
  }

  renderPriorityAssets(items) {
    if (!items.length) {
      this.elements.priorityAssetList.innerHTML = '<p class="empty-state">No application risk is available.</p>';
      return;
    }
    this.elements.priorityAssetList.innerHTML = items.map((item) => `<button class="priority-item" type="button" data-priority-asset="${this.escapeHtml(item.branch_inventory_id)}">
      <span class="priority-score">${this.number(item.max_risk_score)}</span>
      <span class="priority-copy">
        <strong>${this.escapeHtml(item.application || item.repository)}</strong>
        <small>${this.escapeHtml(`${item.organization || ""} / ${item.repository || ""} · ${item.branch || ""}`)}${item.data_types && item.data_types.length ? ` · ${this.escapeHtml(item.data_types.map((value) => this.readable(value)).join(", "))}` : ""}</small>
      </span>
      <span class="priority-meta">${this.number(item.active_findings)} active<br>${this.number(item.overdue_findings)} overdue</span>
    </button>`).join("");
  }

  openPriorityApplicationFindings(branchInventoryId) {
    this.setActiveView("findingsView");
    this.elements.findingSeverityFilter.value = "";
    this.elements.findingStatusFilter.value = "";
    this.elements.findingSearchQuery.value = "";
    this.state.findingDrilldownFilters = {branch_inventory_id: Number(branchInventoryId)};
    this.state.quickFilter = "active";
    document.querySelectorAll("[data-finding-quick-filter]").forEach((button) => {
      button.classList.toggle("active", button.dataset.findingQuickFilter === "active");
    });
    this.searchFindings(0, true);
  }

  openStatusFindings(status) {
    this.setActiveView("findingsView");
    this.state.quickFilter = "all";
    document.querySelectorAll("[data-finding-quick-filter]").forEach((button) => {
      button.classList.toggle("active", button.dataset.findingQuickFilter === "all");
    });
    this.elements.findingSeverityFilter.value = "";
    this.elements.findingStatusFilter.value = status;
    this.elements.findingSearchQuery.value = "";
    this.state.findingDrilldownFilters = {};
    this.searchFindings(0, true);
  }

  renderToolHealth(items) {
    if (!items.length) {
      this.elements.toolHealthGrid.innerHTML = '<p class="empty-state">Import scanner results to establish tool coverage.</p>';
      return;
    }
    this.elements.toolHealthGrid.innerHTML = items.map((item) => {
      const status = item.last_import_status || "not_run";
      const statusClass = status === "failed"
        ? "status-failed"
        : ["processing", "running"].includes(status)
          ? "status-running"
          : status === "completed" ? "status-succeeded" : "idle";
      const source = item.last_import_source ? ` · ${this.readable(item.last_import_source)}` : "";
      const timestamp = item.last_import_completed_at || item.last_import_at || item.last_seen_at;
      const displayName = item.tool_name === "Semgrep" ? "Semgrep Enterprise" : item.tool_name;
      const failedActions = status === "failed"
        ? `<div class="tool-health-actions">
            <button class="ghost small" type="button" data-tool-health-action="configuration">Review connection</button>
            <button class="ghost small" type="button" data-tool-health-action="logs" data-tool-key="${this.escapeHtml(item.tool_key)}" data-tool-name="${this.escapeHtml(displayName)}">Review logging</button>
          </div>`
        : "";
      return `<div class="tool-health-item">
      <span class="tool-health-heading"><strong>${this.escapeHtml(displayName)}</strong><span class="status-chip ${statusClass}">${this.escapeHtml(this.readable(status))}</span></span>
      <span>${this.number(item.covered_assets)} assets covered · ${this.number(item.active_findings)} active findings</span>
      <small>Latest ${this.escapeHtml(source ? `operation${source}` : "import")} ${this.escapeHtml(this.formatDate(timestamp))}${item.last_import_error ? ` · ${this.escapeHtml(item.last_import_error)}` : ""}</small>
      ${failedActions}
    </div>`;
    }).join("");
  }

  async loadConnectors(force = false) {
    if (!force && this.state.busy.has("connectors")) {
      return;
    }
    this.setBusy("connectors", true);
    try {
      const data = await this.postJson("/api/configuration/connectors", {});
      this.state.connectors = {items: data.connectors || [], syncs: data.syncs || [], loaded: true};
      this.state.refreshedAt.connectors = Date.now();
      this.renderConnectors();
    } catch (error) {
      this.elements.connectorGrid.innerHTML = `<p class="empty-state">${this.escapeHtml(error.message || "Scanner configuration could not be loaded.")}</p>`;
      this.notify(error.message || "Scanner configuration could not be loaded.");
    } finally {
      this.setBusy("connectors", false);
    }
  }

  async openConnectorLogs(toolKey, toolName) {
    this.elements.connectorLogsEyebrow.textContent = "Scanner logs";
    this.elements.connectorLogsTitle.textContent = toolName || "Connection history";
    this.elements.connectorLogsBody.innerHTML = '<p class="empty-state">Loading logs…</p>';
    if (!this.elements.connectorLogsDialog.open) {
      this.elements.connectorLogsDialog.showModal();
    }
    try {
      const data = await this.postJson("/api/aspm/connectors/history", {
        ...this.databasePayload(),
        limit: 20,
      });
      const syncs = (data.syncs || []).filter((s) => !toolKey || s.connector_key === toolKey);
      if (!syncs.length) {
        this.elements.connectorLogsBody.innerHTML = '<p class="empty-state">No sync history found for this connector.</p>';
        return;
      }
      this.elements.connectorLogsBody.innerHTML = syncs.map((sync) => {
        const statusClass = sync.status === "failed" ? "status-failed"
          : sync.status === "completed" ? "status-succeeded"
          : "idle";
        const started = sync.started_at ? this.formatDate(sync.started_at) : "Unknown";
        const duration = sync.started_at && sync.completed_at
          ? `${Math.round((new Date(sync.completed_at) - new Date(sync.started_at)) / 1000)}s`
          : null;
        return `<div class="connector-log-entry">
          <div class="connector-log-header">
            <span class="status-chip ${statusClass}">${this.escapeHtml(this.readable(sync.status))}</span>
            <strong>${this.escapeHtml(started)}</strong>
            ${duration ? `<small>${this.escapeHtml(duration)}</small>` : ""}
          </div>
          ${sync.error_message ? `<p class="connector-log-error">${this.escapeHtml(sync.error_message)}</p>` : ""}
          <small>${this.number(sync.findings_imported || 0)} findings · ${this.number(sync.assets_covered || 0)} assets · ${this.escapeHtml(this.readable(sync.connector_key || ""))}</small>
        </div>`;
      }).join("");
    } catch (error) {
      this.elements.connectorLogsBody.innerHTML = `<p class="empty-state">${this.escapeHtml(error.message || "Logs could not be loaded.")}</p>`;
    }
  }

  renderConnectors() {
    if (!this.elements.connectorGrid) {
      return;
    }
    const connectors = this.state.connectors.items || [];
    if (!connectors.length) {
      this.elements.connectorGrid.innerHTML = '<p class="empty-state">No scanner connectors are available.</p>';
      this.elements.connectorSyncSummary.textContent = "";
      return;
    }
    this.elements.connectorGrid.innerHTML = connectors.map((connector) => {
      const syncReady = connector.syncReady === true;
      const managed = connector.configurationSource === "service";
      const importProfile = connector.setup && connector.setup.importFormat;
      const importFormat = importProfile
        ? `<span class="status-chip idle">${this.escapeHtml(importProfile)}</span>`
        : "";
      const action = syncReady
        ? '<span class="status-chip status-succeeded">Ready</span>'
        : `${managed ? '<span class="status-chip idle">Managed</span>' : ""}${importFormat}<button class="ghost small" type="button" data-connector-setup="${this.escapeHtml(connector.key)}">Configure</button>`;
      const selection = `<label class="connector-select"><input type="checkbox" name="connectorSelection" value="${this.escapeHtml(connector.key)}" ${connector.configured ? "checked" : "disabled"} ${syncReady ? "" : "disabled"}><span class="connector-copy"><strong>${this.escapeHtml(connector.name)}</strong><small>${this.escapeHtml(connector.message)}</small></span></label>`;
      return `<article class="connector-item ${connector.configured ? "configured" : "not-configured"}${importProfile ? " report-import-profile" : ""}">
        ${selection}
        <span class="connector-item-action">${action}</span>
      </article>`;
    }).join("");
    const latest = (this.state.connectors.syncs || [])[0];
    this.elements.connectorSyncSummary.textContent = latest
      ? `Latest sync: ${latest.connector_name} · ${this.readable(latest.status)} · ${this.formatDate(latest.completed_at || latest.started_at)}`
      : "No direct scanner sync has run for this account.";
  }

  openConnectorSetup(connectorKey) {
    const connector = (this.state.connectors.items || []).find((item) => item.key === connectorKey);
    if (!connector) {
      return;
    }
    const setup = connector.setup || {type: "other", description: "", fields: []};
    const configuration = connector.configuration || {};
    const secrets = configuration.secrets || {};
    this.elements.connectorSetupKey.value = connector.key;
    this.elements.connectorSetupType.textContent = setup.importFormat || this.readable(setup.type || "scanner setup");
    this.elements.connectorSetupTitle.textContent = `Configure ${connector.name}`;
    this.elements.connectorSetupDescription.textContent = setup.description || "";
    this.elements.connectorSetupStatus.textContent = "";
    this.elements.connectorSetupFields.innerHTML = (setup.fields || []).map((field) => {
      const stored = field.secret && secrets[field.key];
      const value = field.secret ? "" : (configuration[field.key] || "");
      const type = field.secret ? "password" : field.key === "endpoint" ? "url" : "text";
      const required = field.required ? "required" : "";
      const placeholder = stored ? "Stored value" : "";
      return `<label><span>${this.escapeHtml(field.label)}${field.required ? ' <span class="field-badge required">Required</span>' : ' <span class="field-badge optional">Optional</span>'}</span><input data-connector-field="${this.escapeHtml(field.key)}" data-connector-secret="${field.secret ? "true" : "false"}" type="${type}" value="${this.escapeHtml(value)}" placeholder="${this.escapeHtml(placeholder)}" autocomplete="off" ${required}></label>`;
    }).join("");
    if (!this.elements.connectorSetupDialog.open) {
      this.elements.connectorSetupDialog.showModal();
    }
  }

  async saveConnectorSetup() {
    const connector = this.elements.connectorSetupKey.value;
    if (!connector) {
      return;
    }
    const configuration = {};
    this.elements.connectorSetupFields.querySelectorAll("[data-connector-field]").forEach((input) => {
      const value = input.value.trim();
      if (value || input.dataset.connectorSecret !== "true") {
        configuration[input.dataset.connectorField] = value;
      }
    });
    try {
      this.elements.saveConnectorSetup.disabled = true;
      this.elements.connectorSetupStatus.textContent = "Saving configuration";
      await this.postJson("/api/configuration/connectors/save", {connector, configuration});
      this.elements.connectorSetupStatus.textContent = "Saved.";
      await this.loadConnectors(true);
      this.notify("Scanner configuration saved.");
      this.elements.connectorSetupDialog.close();
    } catch (error) {
      this.elements.connectorSetupStatus.textContent = error.message || "Scanner configuration could not be saved.";
    } finally {
      this.elements.saveConnectorSetup.disabled = false;
    }
  }

  async syncConnectors() {
    const connectors = Array.from(document.querySelectorAll('input[name="connectorSelection"]:checked'))
      .map((input) => input.value);
    if (!connectors.length) {
      this.notify("Select at least one configured scanner.");
      return;
    }
    this.elements.syncConnectors.disabled = true;
    this.elements.syncConnectors.textContent = "Syncing scanners";
    this.elements.connectorSyncSummary.textContent = "Pulling findings and correlating them to inventory assets. You can continue using other pages.";
    try {
      const data = await this.postJson("/api/aspm/connectors/sync", {
        ...this.databasePayload(),
        connectors,
      });
      const result = data.sync || {};
      const findings = (result.results || []).reduce((sum, item) => sum + Number(item.findings || 0), 0);
      const errors = result.errors || [];
      this.notify(errors.length
        ? `Scanner sync imported ${this.number(findings)} findings with ${this.number(errors.length)} connector error${errors.length === 1 ? "" : "s"}.`
        : `Scanner sync imported ${this.number(findings)} findings.`);
      await Promise.all([
        this.loadConnectors(true),
        this.loadPosture(true),
        this.searchFindings(0),
        this.loadCoverage(0, true),
        this.loadAssetRisks(0, true),
      ]);
    } catch (error) {
      this.elements.connectorSyncSummary.textContent = error.message || "Scanner sync failed.";
      this.notify(error.message || "Scanner sync failed.");
      await this.loadConnectors(true);
    } finally {
      this.elements.syncConnectors.disabled = false;
      this.elements.syncConnectors.textContent = "Sync ready scanners";
    }
  }

  async testConnections() {
    const connectors = Array.from(document.querySelectorAll('input[name="connectorSelection"]:checked'))
      .map((input) => input.value);
    this.elements.testConnectors.disabled = true;
    this.elements.connectorSyncSummary.textContent = "Testing authenticated scanner connections.";
    try {
      const data = await this.postJson("/api/aspm/connectors/test", {
        ...this.databasePayload(),
        connectors,
      });
      const result = data.connectionTest || {};
      const tested = result.results || [];
      const errors = result.errors || [];
      this.elements.connectorSyncSummary.textContent = errors.length
        ? `${this.number(tested.length)} connection${tested.length === 1 ? "" : "s"} verified; ${this.number(errors.length)} failed.`
        : `${this.number(tested.length)} scanner connection${tested.length === 1 ? "" : "s"} verified.`;
      this.notify(this.elements.connectorSyncSummary.textContent);
    } catch (error) {
      this.elements.connectorSyncSummary.textContent = error.message || "Connection test failed.";
      this.notify(error.message || "Connection test failed.");
    } finally {
      this.elements.testConnectors.disabled = false;
    }
  }

  async loadAssetRisks(offset = 0, force = false) {
    if (!force && this.state.busy.has("assetRisks")) {
      return;
    }
    const requestId = this.state.assetRiskRequest + 1;
    this.state.assetRiskRequest = requestId;
    this.setBusy("assetRisks", true);
    this.elements.assetRiskSummary.textContent = "Loading asset risk profiles";
    try {
      const data = await this.postJson("/api/aspm/assets/risks", {
        ...this.databasePayload(),
        query: this.elements.assetRiskQuery.value.trim(),
        riskBands: this.elements.assetRiskBand.value ? [this.elements.assetRiskBand.value] : [],
        dataTypes: this.elements.assetRiskDataType.value ? [this.elements.assetRiskDataType.value] : [],
        activeOnly: this.state.assetRisks.activeOnly === true,
        limit: this.state.assetRisks.limit,
        offset,
      });
      this.state.assetRisks = {...data.assets, activeOnly: Boolean(data.assets.filters && data.assets.filters.activeOnly), loaded: true, assetRiskRequest: requestId};
      this.state.refreshedAt.assetRisks = Date.now();
      this.renderAssetRisks();
    } catch (error) {
      this.elements.assetRiskSummary.textContent = "Asset risk unavailable";
      this.elements.assetRiskRows.innerHTML = `<tr><td class="database-empty-row" colspan="7">${this.escapeHtml(error.message || "Asset risk profiles could not be loaded.")}</td></tr>`;
      this.notify(error.message || "Asset risk profiles could not be loaded.");
    } finally {
      this.setBusy("assetRisks", false);
    }
  }

  clearAssetRiskFilters() {
    this.elements.assetRiskQuery.value = "";
    this.elements.assetRiskBand.value = "";
    this.elements.assetRiskDataType.value = "";
    this.state.assetRisks.activeOnly = false;
    this.loadAssetRisks(0, true);
  }

  renderAssetRisks() {
    if (!this.elements.assetRiskRows) {
      return;
    }
    const assets = this.state.assetRisks;
    this.elements.assetRiskPageSize.value = String(assets.limit);
    const start = assets.total ? assets.offset + 1 : 0;
    const end = Math.min(assets.offset + assets.rows.length, assets.total);
    this.elements.assetRiskSummary.textContent = `${this.number(start)}-${this.number(end)} of ${this.number(assets.total)} ${assets.activeOnly ? "assets with active findings" : "assets"}`;
    this.elements.assetRiskPagePosition.textContent = `Page ${Math.floor(assets.offset / assets.limit) + 1} of ${Math.max(1, Math.ceil(assets.total / assets.limit))}`;
    this.elements.assetRiskRecordCount.textContent = `${this.number(assets.total)} matching assets`;
    this.elements.assetRiskPrevious.disabled = assets.offset <= 0;
    this.elements.assetRiskNext.disabled = assets.offset + assets.limit >= assets.total;
    if (!assets.rows.length) {
      this.elements.assetRiskRows.innerHTML = '<tr><td class="database-empty-row" colspan="7">No assets match the current risk filters.</td></tr>';
      return;
    }
    this.elements.assetRiskRows.innerHTML = assets.rows.map((asset) => `<tr>
      <td><span class="risk-score-badge risk-${this.classToken(asset.risk_band)}">${this.number(asset.risk_score)}</span></td>
      <td><span class="finding-application"><strong>${this.escapeHtml(asset.application)}</strong><small>${this.escapeHtml(asset.application_types || "Not classified")}</small></span></td>
      <td><span class="finding-application"><strong>${this.escapeHtml(asset.repository)}</strong><small>${this.escapeHtml(`${asset.organization || ""} · ${asset.branch || ""}`)}</small></span></td>
      <td>${this.number(asset.active_findings)}<small class="table-subtext">${this.number(asset.critical_findings)} critical · ${this.number(asset.high_findings)} high</small></td>
      <td>${this.number(asset.data_sensitivity_score)} / 100</td>
      <td>${this.escapeHtml((asset.data_types || []).map((item) => this.readable(item)).join("; ") || "Not observed")}</td>
      <td>${this.number(asset.context_score)} / 100</td>
    </tr>`).join("");
  }

  openFindings(openImport = false) {
    this.setActiveView("findingsView");
    if (openImport) {
      this.toggleImport(true);
    }
  }

  toggleImport(open) {
    this.elements.findingImportPanel.hidden = !open;
    this.elements.findingImportPanel.classList.toggle("hidden", !open);
    if (open) {
      this.elements.findingImportFile.focus();
    }
  }

  fileSelected() {
    const file = this.elements.findingImportFile.files[0];
    this.elements.submitFindingImport.disabled = !file;
    this.elements.findingImportStatus.textContent = file
      ? `${file.name} · ${this.fileSize(file.size)}`
      : "Choose a scanner result file.";
  }

  async importFindings() {
    const file = this.elements.findingImportFile.files[0];
    if (!file) {
      this.notify("Choose a scanner result file first.");
      return;
    }
    if (file.size > 20 * 1024 * 1024) {
      this.notify("Scanner result files must be 20 MB or smaller in the UI.");
      return;
    }
    this.elements.submitFindingImport.disabled = true;
    this.elements.findingImportStatus.textContent = "Reading and validating results";
    try {
      const documentData = JSON.parse(await file.text());
      const toolName = this.elements.findingImportTool.value.trim();
      const payload = {
        ...this.databasePayload(),
        format: this.elements.findingImportFormat.value,
        document: documentData,
        completeSnapshot: this.elements.findingCompleteSnapshot.checked,
        context: {
          provider: this.elements.findingContextProvider.value,
          organization: this.elements.findingContextOrganization.value.trim(),
          project: this.elements.findingContextProject.value.trim(),
          repository: this.elements.findingContextRepository.value.trim(),
          branch: this.elements.findingContextBranch.value.trim(),
        },
      };
      if (toolName) {
        payload.tool = {name: toolName, key: toolName};
      }
      const data = await this.postJson("/api/aspm/findings/import", payload);
      const result = data.import;
      this.elements.findingImportStatus.textContent = `${this.number(result.findings)} processed · ${this.number(result.inserted)} new · ${this.number(result.updated)} updated`;
      this.notify(`Imported ${this.number(result.findings)} findings from ${result.tool.name}.`);
      await Promise.all([this.loadPosture(true), this.searchFindings(0), this.loadCoverage(0, true)]);
    } catch (error) {
      this.elements.findingImportStatus.textContent = error.message || "Import failed";
      this.notify(error.message || "Scanner results could not be imported.");
    } finally {
      this.elements.submitFindingImport.disabled = false;
    }
  }

  async searchFindings(offset = 0, force = false, cursor = undefined) {
    if (!force && this.state.busy.has("findings")) {
      return;
    }
    const requestId = this.state.findingRequest + 1;
    this.state.findingRequest = requestId;
    this.setBusy("findings", true);
    this.elements.findingResultSummary.textContent = "Loading findings";
    try {
      const filters = this.findingFilters();
      const includeFacets = !this.state.findings.loaded;
      const pageIndex = Math.floor(offset / this.state.findings.limit);
      const pageCursor = cursor === undefined
        ? this.state.findingCursors[pageIndex] || null
        : cursor;
      const data = await this.postJson("/api/aspm/findings/search", {
        ...this.databasePayload(),
        query: this.elements.findingSearchQuery.value.trim(),
        filters,
        limit: this.state.findings.limit,
        offset,
        includeFacets,
        includeTotal: false,
        cursor: pageCursor,
      });
      if (requestId !== this.state.findingRequest) {
        return;
      }
      const returnedFacets = data.findings.facets || {};
      const facets = Object.keys(returnedFacets).length
        ? returnedFacets
        : this.state.findings.facets || {};
      this.state.findings = {...data.findings, facets, loaded: true};
      if (offset === 0) {
        this.state.findingCursors = [null];
      }
      this.state.findingCursors[pageIndex] = pageCursor;
      if (data.findings.nextCursor) {
        this.state.findingCursors[pageIndex + 1] = data.findings.nextCursor;
      } else {
        this.state.findingCursors.length = pageIndex + 1;
      }
      this.state.findingFilters = filters;
      this.state.refreshedAt.findings = Date.now();
      this.renderFindings();
    } catch (error) {
      if (requestId !== this.state.findingRequest) {
        return;
      }
      this.elements.findingResultSummary.textContent = "Findings unavailable";
      this.elements.findingResultRows.innerHTML = `<tr><td class="database-empty-row" colspan="9">${this.escapeHtml(error.message || "Findings could not be loaded.")}</td></tr>`;
      this.notify(error.message || "Findings could not be loaded.");
    } finally {
      if (requestId === this.state.findingRequest) {
        this.setBusy("findings", false);
      }
    }
  }

  previousFindingsPage() {
    const findings = this.state.findings;
    const offset = Math.max(0, findings.offset - findings.limit);
    const pageIndex = Math.floor(offset / findings.limit);
    this.searchFindings(offset, false, this.state.findingCursors[pageIndex] || null);
  }

  nextFindingsPage() {
    const findings = this.state.findings;
    const hasTotal = Number.isInteger(findings.total);
    const hasMore = typeof findings.hasMore === "boolean"
      ? findings.hasMore
      : hasTotal && findings.offset + findings.limit < findings.total;
    if (!hasMore) {
      return;
    }
    this.searchFindings(
      findings.offset + findings.limit,
      false,
      findings.nextCursor || null,
    );
  }

  findingFilters() {
    const filters = {
      ...this.quickFilterCriteria(this.state.quickFilter),
      ...this.state.findingDrilldownFilters,
    };
    if (this.elements.findingSeverityFilter.value) {
      filters.severities = [this.elements.findingSeverityFilter.value];
    }
    if (this.elements.findingStatusFilter.value) {
      filters.statuses = [this.elements.findingStatusFilter.value];
    }
    if (this.elements.findingToolFilter.value) {
      filters.tools = [this.elements.findingToolFilter.value];
    }
    return filters;
  }

  quickFilterCriteria(name) {
    const active = ["open", "triaged", "in_progress"];
    return {
      active: {statuses: active},
      critical: {statuses: active, severities: ["critical"]},
      overdue: {statuses: active, overdue: true},
      unassigned: {statuses: active, unassigned: true},
      unlinked: {statuses: active, has_asset: false},
      all: {},
    }[name] || {statuses: active};
  }

  activateQuickFilter(name) {
    this.state.quickFilter = name;
    this.state.findingDrilldownFilters = {};
    document.querySelectorAll("[data-finding-quick-filter]").forEach((button) => {
      button.classList.toggle("active", button.dataset.findingQuickFilter === name);
    });
    this.searchFindings(0);
  }

  clearFindingFilters() {
    this.elements.findingSearchQuery.value = "";
    this.elements.findingSeverityFilter.value = "";
    this.elements.findingStatusFilter.value = "";
    this.elements.findingToolFilter.value = "";
    this.state.findingDrilldownFilters = {};
    this.activateQuickFilter("active");
  }

  renderFindings() {
    if (!this.elements.findingResultRows) {
      return;
    }
    const findings = this.state.findings;
    this.populateToolFilter(findings.facets && findings.facets.tools || []);
    this.elements.findingPageSize.value = String(findings.limit);
    const hasTotal = Number.isInteger(findings.total);
    const start = findings.rows.length ? findings.offset + 1 : 0;
    const end = findings.offset + findings.rows.length;
    const page = Math.floor(findings.offset / findings.limit) + 1;
    const hasMore = typeof findings.hasMore === "boolean"
      ? findings.hasMore
      : hasTotal && findings.offset + findings.limit < findings.total;
    this.elements.findingResultSummary.textContent = hasTotal
      ? `${this.number(start)}-${this.number(end)} of ${this.number(findings.total)} findings`
      : findings.rows.length ? `${this.number(start)}-${this.number(end)} findings` : "No findings";
    this.elements.findingPagePosition.textContent = hasTotal
      ? `Page ${page} of ${Math.max(1, Math.ceil(findings.total / findings.limit))}`
      : `Page ${page}`;
    this.elements.findingRecordCount.textContent = hasTotal
      ? `${this.number(findings.total)} matching records`
      : hasMore ? "More matching records available" : `${this.number(end)} matching records`;
    this.elements.findingPrevious.disabled = findings.offset <= 0;
    this.elements.findingNext.disabled = !hasMore;
    if (!findings.rows.length) {
      this.elements.findingResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="9">No findings match the current filters.</td></tr>';
      return;
    }
    this.elements.findingResultRows.innerHTML = findings.rows.map((row) => {
      const correlationContext = [
        row.correlated_branch && `Branch ${row.correlated_branch}`,
        row.primary_web_domain,
      ].filter(Boolean).join(" | ") || "No linked inventory asset";
      const responsibility = row.technical_owner
        ? `Technical: ${row.technical_owner}`
        : row.business_owner ? `Business: ${row.business_owner}` : "No owner assigned";
      const developers = row.contributing_developers || "No branch contributors recorded";
      return `<tr data-finding-id="${this.escapeHtml(row.finding_id)}" tabindex="0">
      <td><span class="risk-score-badge risk-${this.classToken(row.risk_band)}">${this.number(row.risk_score)}</span></td>
      <td><span class="finding-title"><strong>${this.escapeHtml(row.title)}</strong><small>${this.escapeHtml(row.rule_id || row.category || "No rule identifier")}</small></span></td>
      <td><span class="finding-application"><strong>${this.escapeHtml(row.application)}</strong><small>${this.escapeHtml(`${row.organization || ""} / ${row.repository || "Unlinked"}`)}</small></span></td>
      <td><span class="finding-application"><strong>${this.escapeHtml(this.readable(row.correlation_method || "unlinked"))}</strong><small>${this.escapeHtml(correlationContext)}</small></span></td>
      <td class="finding-responsibility"><span><strong>${this.escapeHtml(responsibility)}</strong><small>${this.escapeHtml(developers)}</small></span></td>
      <td><span class="severity-badge severity-${this.classToken(row.severity)}">${this.escapeHtml(row.severity)}</span></td>
      <td><span class="workflow-badge">${this.escapeHtml(this.readable(row.status))}</span></td>
      <td>${this.escapeHtml(row.tool_name)}</td>
      <td>${this.escapeHtml(row.due_at ? this.formatDate(row.due_at) : "Not set")}</td>
    </tr>`;
    }).join("");
  }

  populateToolFilter(items) {
    const selected = this.elements.findingToolFilter.value;
    this.elements.findingToolFilter.innerHTML = '<option value="">All tools</option>' + items.map((item) => `<option value="${this.escapeHtml(item.value)}">${this.escapeHtml(item.label || item.value)} (${this.number(item.count)})</option>`).join("");
    if (Array.from(this.elements.findingToolFilter.options).some((option) => option.value === selected)) {
      this.elements.findingToolFilter.value = selected;
    }
  }

  openFindingFromEvent(event) {
    const row = event.target.closest("tr[data-finding-id]");
    if (row) {
      this.openFinding(row.dataset.findingId);
    }
  }

  async openFinding(findingId) {
    try {
      const data = await this.postJson("/api/aspm/findings/detail", {
        ...this.databasePayload(),
        findingId,
      });
      this.state.activeFinding = data.finding;
      this.renderFindingDetail(data.finding, data.events || []);
      if (!this.elements.findingDialog.open) {
        this.elements.findingDialog.showModal();
      }
    } catch (error) {
      this.notify(error.message || "Finding details could not be loaded.");
    }
  }

  renderFindingDetail(finding, events) {
    this.elements.findingDialogTitle.textContent = finding.title || "Finding details";
    const fields = [
      ["Risk", `${finding.risk_score} / 100 · ${this.readable(finding.risk_band)}`],
      ["Severity", this.readable(finding.severity)],
      ["Application", finding.application],
      ["Repository", `${finding.organization || ""} / ${finding.repository || "Unlinked"}`],
      ["Location", `${finding.path || "Not provided"}${finding.start_line ? `:${finding.start_line}` : ""}`],
      ["Correlation", `${this.readable(finding.correlation_method || "unlinked")} · ${finding.correlated_branch || "No branch"}`],
      ["Branch responsibility", [finding.technical_owner && `Technical: ${finding.technical_owner}`, finding.business_owner && `Business: ${finding.business_owner}`, finding.contributing_developers].filter(Boolean).join(" | ") || "Not provided"],
      ["Tool", `${finding.tool_name} · ${finding.rule_id || "No rule ID"}`],
      ["Identifiers", [finding.cwes, finding.cves].filter(Boolean).join("; ") || "Not provided"],
      ["Package", finding.package_name ? `${finding.package_name} ${finding.package_version || ""}`.trim() : "Not applicable"],
      ["First seen", this.formatDate(finding.first_seen)],
      ["Last seen", this.formatDate(finding.last_seen)],
      ["Description", finding.description || "No description provided", true],
      ["Remediation", finding.remediation || "No remediation guidance provided", true],
    ];
    this.elements.findingDetailSummary.innerHTML = fields.map(([label, value, full]) => `<div class="finding-detail-item${full ? " full" : ""}"><span>${this.escapeHtml(label)}</span><strong>${this.escapeHtml(value)}</strong></div>`).join("");
    this.elements.findingWorkflowStatus.innerHTML = [
      ["open", "Open"], ["triaged", "Triaged"], ["in_progress", "In progress"],
      ["resolved", "Resolved"], ["accepted", "Risk accepted"], ["false_positive", "False positive"],
    ].map(([value, label]) => `<option value="${value}">${label}</option>`).join("");
    this.elements.findingWorkflowStatus.value = finding.status;
    this.elements.findingWorkflowAssignee.value = finding.assignee || "";
    this.elements.findingWorkflowDue.value = finding.due_at ? finding.due_at.slice(0, 10) : "";
    this.elements.findingWorkflowNote.value = "";
    this.elements.findingWorkflowMessage.textContent = "Changes are written to the audit trail.";
    this.elements.findingHistory.innerHTML = events.length
      ? events.map((event) => `<div class="finding-history-item"><time>${this.escapeHtml(this.formatDate(event.created_at))}</time><span><strong>${this.escapeHtml(this.readable(event.event_type))} · ${this.escapeHtml(event.actor)}</strong><small>${this.escapeHtml(event.note || `${this.readable(event.from_status)} to ${this.readable(event.to_status)}`)}</small></span></div>`).join("")
      : '<p class="empty-state">No workflow history is available.</p>';
  }

  async saveFindingWorkflow() {
    const finding = this.state.activeFinding;
    if (!finding) {
      return;
    }
    this.elements.saveFindingWorkflow.disabled = true;
    this.elements.findingWorkflowMessage.textContent = "Saving workflow";
    try {
      await this.postJson("/api/aspm/findings/update", {
        ...this.databasePayload(),
        findingId: finding.finding_id,
        status: this.elements.findingWorkflowStatus.value,
        assignee: this.elements.findingWorkflowAssignee.value.trim(),
        dueAt: this.elements.findingWorkflowDue.value || null,
        note: this.elements.findingWorkflowNote.value.trim(),
      });
      this.elements.findingWorkflowMessage.textContent = "Workflow saved.";
      this.notify("Finding workflow updated.");
      await Promise.all([this.openFinding(finding.finding_id), this.searchFindings(this.state.findings.offset), this.loadPosture(true)]);
    } catch (error) {
      this.elements.findingWorkflowMessage.textContent = error.message || "Workflow update failed";
      this.notify(error.message || "Finding workflow could not be updated.");
    } finally {
      this.elements.saveFindingWorkflow.disabled = false;
    }
  }

  async exportFindings(format) {
    try {
      const response = await fetch("/api/aspm/findings/export", {
        method: "POST",
        headers: this.authHeaders(true),
        body: JSON.stringify({
          ...this.databasePayload(),
          format,
          query: this.elements.findingSearchQuery.value.trim(),
          filters: this.findingFilters(),
        }),
      });
      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || "Finding export failed.");
      }
      this.downloadBlob(await response.blob(), `aspm_findings_export.${format}`);
    } catch (error) {
      this.notify(error.message || "Finding export failed.");
    }
  }

  async loadCoverage(offset = 0, force = false) {
    if (!force && this.state.busy.has("coverage")) {
      return;
    }
    this.setBusy("coverage", true);
    try {
      const data = await this.postJson("/api/aspm/coverage", {
        ...this.databasePayload(),
        limit: this.state.coverage.limit,
        offset,
      });
      this.state.coverage = {...data.coverage, loaded: true};
      this.state.refreshedAt.coverage = Date.now();
      this.renderCoverage();
    } catch (error) {
      this.elements.coverageResultSummary.textContent = "Coverage unavailable";
      this.elements.coverageResultRows.innerHTML = `<tr><td class="database-empty-row" colspan="7">${this.escapeHtml(error.message || "Coverage could not be loaded.")}</td></tr>`;
      this.notify(error.message || "Scanner coverage could not be loaded.");
    } finally {
      this.setBusy("coverage", false);
    }
  }

  async loadAssetProfile(asset) {
    this.state.activeAsset = asset || null;
    const branchInventoryId = Number(asset && asset.branch_inventory_id || 0);
    this.elements.assetProfile.hidden = !branchInventoryId;
    if (!branchInventoryId) {
      return;
    }
    this.elements.assetProfileStatus.textContent = "Loading";
    this.elements.assetProfileStatus.className = "status-chip status-running";
    try {
      const data = await this.postJson("/api/aspm/assets/profile", {
        ...this.databasePayload(),
        branchInventoryId,
      });
      const profile = data.profile;
      this.elements.assetCriticality.value = profile.criticality || "medium";
      this.elements.assetInternetExposure.value = profile.internet_exposed === null
        ? "auto"
        : String(Boolean(profile.internet_exposed));
      this.elements.assetDataClassification.value = profile.data_classification || "internal";
      this.elements.assetBusinessOwner.value = profile.business_owner || "";
      this.elements.assetTechnicalOwner.value = profile.technical_owner || "";
      this.elements.assetSecurityTags.value = Array.isArray(profile.tags) ? profile.tags.join(", ") : "";
      const dataTypes = Array.isArray(profile.data_types)
        ? profile.data_types.map((item) => this.readable(item)).join("; ")
        : "";
      this.elements.assetProfileRisk.innerHTML = `<div><span>Contextual risk</span><strong>${this.number(profile.risk_score)} / 100 · ${this.escapeHtml(this.readable(profile.risk_band))}</strong></div>
        <div><span>Technical</span><strong>${this.number(profile.technical_score)} / 100</strong></div>
        <div><span>Data sensitivity</span><strong>${this.number(profile.data_sensitivity_score)} / 100</strong></div>
        <div><span>Observed data</span><strong>${this.escapeHtml(dataTypes || "Not observed")}</strong></div>`;
      this.elements.assetProfileStatus.textContent = "Ready";
      this.elements.assetProfileStatus.className = "status-chip status-succeeded";
      this.elements.assetProfileMessage.textContent = profile.internet_exposed === null && profile.domain_detected
        ? "Domain evidence currently treats this application as internet exposed."
        : "Risk is recalculated when this profile changes.";
    } catch (error) {
      this.elements.assetProfileStatus.textContent = "Unavailable";
      this.elements.assetProfileStatus.className = "status-chip status-failed";
      this.elements.assetProfileMessage.textContent = error.message || "Security context could not be loaded.";
    }
  }

  async saveAssetProfile() {
    const branchInventoryId = Number(this.state.activeAsset && this.state.activeAsset.branch_inventory_id || 0);
    if (!branchInventoryId) {
      return;
    }
    const exposure = this.elements.assetInternetExposure.value;
    this.elements.saveAssetProfile.disabled = true;
    this.elements.assetProfileMessage.textContent = "Saving security context";
    try {
      await this.postJson("/api/aspm/assets/profile", {
        ...this.databasePayload(),
        branchInventoryId,
        profile: {
          criticality: this.elements.assetCriticality.value,
          internetExposed: exposure === "auto" ? null : exposure === "true",
          dataClassification: this.elements.assetDataClassification.value,
          businessOwner: this.elements.assetBusinessOwner.value.trim(),
          technicalOwner: this.elements.assetTechnicalOwner.value.trim(),
          tags: this.elements.assetSecurityTags.value.split(/[,;]/).map((item) => item.trim()).filter(Boolean),
        },
      });
      this.elements.assetProfileStatus.textContent = "Saved";
      this.elements.assetProfileStatus.className = "status-chip status-succeeded";
      this.elements.assetProfileMessage.textContent = "Security context saved and finding risk recalculated.";
      this.notify("Application security context updated.");
      await Promise.all([
        this.loadPosture(true),
        this.searchFindings(this.state.findings.offset),
        this.loadAssetRisks(this.state.assetRisks.offset, true),
      ]);
    } catch (error) {
      this.elements.assetProfileStatus.textContent = "Failed";
      this.elements.assetProfileStatus.className = "status-chip status-failed";
      this.elements.assetProfileMessage.textContent = error.message || "Security context could not be saved.";
      this.notify(error.message || "Security context could not be saved.");
    } finally {
      this.elements.saveAssetProfile.disabled = false;
    }
  }

  renderCoverage() {
    if (!this.elements.coverageResultRows) {
      return;
    }
    const coverage = this.state.coverage;
    const summary = coverage.summary || {};
    this.elements.coverageCurrent.textContent = this.number(summary.current_assets);
    this.elements.coverageStale.textContent = this.number(summary.stale_assets);
    this.elements.coverageUntested.textContent = this.number(summary.untested_assets);
    this.elements.coveragePercent.textContent = `${Number(summary.coverage_percent || 0).toLocaleString()}%`;
    this.elements.coverageResultSummary.textContent = `${this.number(coverage.total)} inventoried applications`;
    this.elements.coveragePagePosition.textContent = `Page ${Math.floor(coverage.offset / coverage.limit) + 1} of ${Math.max(1, Math.ceil(coverage.total / coverage.limit))}`;
    this.elements.coverageRecordCount.textContent = `${this.number(coverage.total)} assets`;
    this.elements.coveragePrevious.disabled = coverage.offset <= 0;
    this.elements.coverageNext.disabled = coverage.offset + coverage.limit >= coverage.total;
    if (!coverage.rows.length) {
      this.elements.coverageResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="7">No inventory assets are available.</td></tr>';
      return;
    }
    this.elements.coverageResultRows.innerHTML = coverage.rows.map((row) => `<tr>
      <td><strong>${this.escapeHtml(row.application)}</strong></td>
      <td>${this.escapeHtml(`${row.organization || ""} / ${row.repository || ""}`)}</td>
      <td>${this.escapeHtml(row.branch)}</td>
      <td>${this.escapeHtml(row.application_types || "Not classified")}</td>
      <td>${this.escapeHtml(row.tools || "No scanner")}</td>
      <td>${this.escapeHtml(row.last_scan_at ? this.formatDate(row.last_scan_at) : "Never")}</td>
      <td><span class="coverage-badge coverage-${this.classToken(row.coverage_status)}">${this.escapeHtml(this.readable(row.coverage_status))}</span></td>
    </tr>`).join("");
  }

  async postJson(url, payload) {
    const response = await fetch(url, {
      method: "POST",
      headers: this.authHeaders(true),
      body: JSON.stringify(payload),
    });
    let data = {};
    try {
      data = await response.json();
    } catch (error) {
      data = {};
    }
    if (!response.ok) {
      throw new Error(data.error || `Request failed with status ${response.status}.`);
    }
    return data;
  }

  setBusy(key, busy) {
    if (busy) {
      this.state.busy.add(key);
    } else {
      this.state.busy.delete(key);
    }
  }

  number(value) {
    return Number(value || 0).toLocaleString();
  }

  readable(value) {
    return String(value || "Not set").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  classToken(value) {
    return String(value || "unknown").toLowerCase().replace(/[^a-z0-9-]+/g, "-");
  }

  fileSize(value) {
    const bytes = Number(value || 0);
    if (bytes < 1024) {
      return `${bytes} B`;
    }
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  }
}
