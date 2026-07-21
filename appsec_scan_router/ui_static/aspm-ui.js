export class AspmWorkspace {
  constructor(dependencies) {
    this.databasePayload = dependencies.databasePayload;
    this.authHeaders = dependencies.authHeaders;
    this.notify = dependencies.notify;
    this.escapeHtml = dependencies.escapeHtml;
    this.formatDate = dependencies.formatDate;
    this.downloadBlob = dependencies.downloadBlob;
    this.setActiveView = dependencies.setActiveView;
    this.state = {
      posture: null,
      findings: {rows: [], total: 0, limit: 100, offset: 0, facets: {}, loaded: false},
      coverage: {rows: [], total: 0, limit: 100, offset: 0, summary: {}, loaded: false},
      findingFilters: {},
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
        "postureStatus", "refreshPosture", "postureCritical", "postureHigh",
        "postureAffectedAssets", "postureAssetContext", "postureOverdue",
        "postureCoverage", "postureAverageRisk", "riskDistribution",
        "statusDistribution", "priorityAssetList", "toolHealthGrid",
        "viewAllFindings", "openFindingImport", "toggleFindingImport",
        "findingImportPanel", "closeFindingImport", "findingImportFormat",
        "findingImportTool", "findingImportFile", "findingCompleteSnapshot",
        "findingContextProvider", "findingContextOrganization",
        "findingContextProject", "findingContextRepository", "findingContextBranch",
        "findingImportStatus", "submitFindingImport", "findingSearchQuery",
        "findingSeverityFilter", "findingStatusFilter", "findingToolFilter",
        "searchFindings", "clearFindingFilters", "findingResultSummary",
        "findingResultRows", "findingPrevious", "findingNext",
        "findingPagePosition", "findingRecordCount", "findingDialog",
        "findingDialogTitle", "closeFindingDialog", "findingDetailSummary",
        "findingWorkflowStatus", "findingWorkflowAssignee", "findingWorkflowDue",
        "findingWorkflowNote", "findingWorkflowMessage", "saveFindingWorkflow",
        "findingHistory", "refreshCoverage", "coverageCurrent", "coverageStale",
        "coverageUntested", "coveragePercent", "coverageResultSummary",
        "coverageResultRows", "coveragePrevious", "coverageNext",
        "coveragePagePosition", "coverageRecordCount",
        "assetProfile", "assetProfileStatus", "assetCriticality",
        "assetInternetExposure", "assetDataClassification", "assetBusinessOwner",
        "assetTechnicalOwner", "assetSecurityTags", "assetProfileMessage",
        "saveAssetProfile",
      ].map((id) => [id, document.querySelector(`#${id}`)])
    );
    if (!this.elements.refreshPosture) {
      return;
    }
    this.elements.refreshPosture.addEventListener("click", () => this.loadPosture(true));
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
    this.elements.findingPrevious.addEventListener("click", () => {
      this.searchFindings(Math.max(0, this.state.findings.offset - this.state.findings.limit));
    });
    this.elements.findingNext.addEventListener("click", () => {
      this.searchFindings(this.state.findings.offset + this.state.findings.limit);
    });
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
    this.elements.coveragePrevious.addEventListener("click", () => {
      this.loadCoverage(Math.max(0, this.state.coverage.offset - this.state.coverage.limit));
    });
    this.elements.coverageNext.addEventListener("click", () => {
      this.loadCoverage(this.state.coverage.offset + this.state.coverage.limit);
    });
    this.elements.saveAssetProfile.addEventListener("click", () => this.saveAssetProfile());
  }

  async initialize() {
    await Promise.all([this.loadPosture(), this.searchFindings(0), this.loadCoverage(0)]);
  }

  reset() {
    this.state.posture = null;
    this.state.findings = {rows: [], total: 0, limit: 100, offset: 0, facets: {}, loaded: false};
    this.state.coverage = {rows: [], total: 0, limit: 100, offset: 0, summary: {}, loaded: false};
    this.state.activeFinding = null;
    this.state.activeAsset = null;
    this.renderPosture();
    this.renderFindings();
    this.renderCoverage();
  }

  onViewActivated(viewId) {
    const stale = (key) => Date.now() - Number(this.state.refreshedAt[key] || 0) > 30000;
    if (viewId === "postureView" && stale("posture")) {
      this.loadPosture();
    } else if (viewId === "findingsView" && stale("findings")) {
      this.searchFindings(this.state.findings.offset);
    } else if (viewId === "coverageView" && stale("coverage")) {
      this.loadCoverage(this.state.coverage.offset);
    }
  }

  async refreshVisible() {
    const active = document.querySelector(".tab-view.active");
    this.onViewActivated(active ? active.id : "postureView");
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
    if (!items.length) {
      this.elements.riskDistribution.innerHTML = '<span class="empty-inline">No findings imported</span>';
      return;
    }
    const total = items.reduce((sum, item) => sum + Number(item.count || 0), 0) || 1;
    const order = ["critical", "high", "medium", "low", "info"];
    const counts = new Map(items.map((item) => [item.name, Number(item.count || 0)]));
    this.elements.riskDistribution.innerHTML = order.map((severity) => {
      const count = counts.get(severity) || 0;
      const width = Math.max(0, Math.round((count / total) * 100));
      return `<div class="risk-bar" data-risk="${severity}">
        <span class="risk-bar-label">${severity}</span>
        <span class="risk-bar-track"><span class="risk-bar-fill" style="width:${width}%"></span></span>
        <span class="risk-bar-count">${this.number(count)}</span>
      </div>`;
    }).join("");
  }

  renderStatusDistribution(items) {
    this.elements.statusDistribution.innerHTML = items.length
      ? items.slice(0, 6).map((item) => `<div><span>${this.readable(item.name)}</span><strong>${this.number(item.count)}</strong></div>`).join("")
      : "";
  }

  renderPriorityAssets(items) {
    if (!items.length) {
      this.elements.priorityAssetList.innerHTML = '<p class="empty-state">No application risk is available.</p>';
      return;
    }
    this.elements.priorityAssetList.innerHTML = items.map((item) => `<div class="priority-item">
      <span class="priority-score">${this.number(item.max_risk_score)}</span>
      <span class="priority-copy">
        <strong>${this.escapeHtml(item.application || item.repository)}</strong>
        <small>${this.escapeHtml(`${item.organization || ""} / ${item.repository || ""} · ${item.branch || ""}`)}</small>
      </span>
      <span class="priority-meta">${this.number(item.active_findings)} active<br>${this.number(item.overdue_findings)} overdue</span>
    </div>`).join("");
  }

  renderToolHealth(items) {
    if (!items.length) {
      this.elements.toolHealthGrid.innerHTML = '<p class="empty-state">Import scanner results to establish tool coverage.</p>';
      return;
    }
    this.elements.toolHealthGrid.innerHTML = items.map((item) => `<div class="tool-health-item">
      <span class="tool-health-heading"><strong>${this.escapeHtml(item.tool_name)}</strong><span class="status-chip ${item.last_import_status === "failed" ? "status-failed" : "status-succeeded"}">${this.escapeHtml(this.readable(item.last_import_status || "ready"))}</span></span>
      <span>${this.number(item.covered_assets)} assets covered · ${this.number(item.active_findings)} active findings</span>
      <small>Last import ${this.escapeHtml(this.formatDate(item.last_import_at || item.last_seen_at))}${item.last_import_error ? ` · ${this.escapeHtml(item.last_import_error)}` : ""}</small>
    </div>`).join("");
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

  async searchFindings(offset = 0) {
    if (this.state.busy.has("findings")) {
      return;
    }
    this.setBusy("findings", true);
    this.elements.findingResultSummary.textContent = "Loading findings";
    try {
      const filters = this.findingFilters();
      const data = await this.postJson("/api/aspm/findings/search", {
        ...this.databasePayload(),
        query: this.elements.findingSearchQuery.value.trim(),
        filters,
        limit: this.state.findings.limit,
        offset,
        includeFacets: true,
      });
      this.state.findings = {...data.findings, loaded: true};
      this.state.findingFilters = filters;
      this.state.refreshedAt.findings = Date.now();
      this.renderFindings();
    } catch (error) {
      this.elements.findingResultSummary.textContent = "Findings unavailable";
      this.elements.findingResultRows.innerHTML = `<tr><td class="database-empty-row" colspan="7">${this.escapeHtml(error.message || "Findings could not be loaded.")}</td></tr>`;
      this.notify(error.message || "Findings could not be loaded.");
    } finally {
      this.setBusy("findings", false);
    }
  }

  findingFilters() {
    const filters = {...this.quickFilterCriteria(this.state.quickFilter)};
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
    this.activateQuickFilter("active");
  }

  renderFindings() {
    if (!this.elements.findingResultRows) {
      return;
    }
    const findings = this.state.findings;
    this.populateToolFilter(findings.facets && findings.facets.tools || []);
    const start = findings.total ? findings.offset + 1 : 0;
    const end = Math.min(findings.offset + findings.rows.length, findings.total);
    this.elements.findingResultSummary.textContent = `${this.number(start)}-${this.number(end)} of ${this.number(findings.total)} findings`;
    this.elements.findingPagePosition.textContent = `Page ${Math.floor(findings.offset / findings.limit) + 1} of ${Math.max(1, Math.ceil(findings.total / findings.limit))}`;
    this.elements.findingRecordCount.textContent = `${this.number(findings.total)} matching records`;
    this.elements.findingPrevious.disabled = findings.offset <= 0;
    this.elements.findingNext.disabled = findings.offset + findings.limit >= findings.total;
    if (!findings.rows.length) {
      this.elements.findingResultRows.innerHTML = '<tr><td class="database-empty-row" colspan="7">No findings match the current filters.</td></tr>';
      return;
    }
    this.elements.findingResultRows.innerHTML = findings.rows.map((row) => `<tr data-finding-id="${this.escapeHtml(row.finding_id)}" tabindex="0">
      <td><span class="risk-score-badge risk-${this.classToken(row.risk_band)}">${this.number(row.risk_score)}</span></td>
      <td><span class="finding-title"><strong>${this.escapeHtml(row.title)}</strong><small>${this.escapeHtml(row.rule_id || row.category || "No rule identifier")}</small></span></td>
      <td><span class="finding-application"><strong>${this.escapeHtml(row.application)}</strong><small>${this.escapeHtml(`${row.organization || ""} / ${row.repository || "Unlinked"}`)}</small></span></td>
      <td><span class="severity-badge severity-${this.classToken(row.severity)}">${this.escapeHtml(row.severity)}</span></td>
      <td><span class="workflow-badge">${this.escapeHtml(this.readable(row.status))}</span></td>
      <td>${this.escapeHtml(row.tool_name)}</td>
      <td>${this.escapeHtml(row.due_at ? this.formatDate(row.due_at) : "Not set")}</td>
    </tr>`).join("");
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
      await Promise.all([this.loadPosture(true), this.searchFindings(this.state.findings.offset)]);
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
