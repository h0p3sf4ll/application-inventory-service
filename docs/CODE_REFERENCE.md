# Code Reference

This reference describes the runtime libraries, Python modules, classes, functions, methods, and browser UI functions that make up Application Inventory Service.

## Runtime Libraries

- `cryptography`: Encrypts saved provider tokens with Fernet for UI users.
- `defusedxml`: Safely parses repository-controlled XML manifest files.
- `openpyxl`: Creates and updates XLSX inventory workbooks.
- `psycopg[binary]`: Connects to PostgreSQL and writes normalized inventory rows.
- `requests`: Calls Azure DevOps, GitHub Enterprise, OAuth, and app-store endpoints over HTTPS.

## Python Modules

### `ado_mobile_scanner`
Compatibility command module that re-exports the scanner API and starts the CLI when executed directly.

### `mobile_app_inventory_tracer`
Compatibility command module retained for earlier package users and scripts.

### `application_inventory_service.__init__`
Public import shim for the current package name.

### `application_inventory_service.__main__`
Executes the Application Inventory Service CLI through `python -m application_inventory_service`.

### `mobile_scanner.__init__`
Legacy package shim that re-exports the scanner API.

### `mobile_scanner.__main__`
Legacy module entry point for `python -m mobile_scanner`.

### `appsec_scan_router.__init__`
Public SDK surface that re-exports scanner, reporting, provider, metadata, and UI helpers.

### `appsec_scan_router.__main__`
Module entry point that dispatches to the CLI.

### `appsec_scan_router.activity`
Commit activity utilities for contributor extraction and last-updated timestamps.

Functions:
- `extract_repo_activity(commits)`: Extracts structured metadata from manifests, commits, or report rows.
- `format_developer(person)`: Formats values for logs, reports, or API responses.
- `developer_identity_key(person, fallback)`: Function that supports developer identity key behavior.
- `parse_ado_datetime(value)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `format_ado_datetime(value)`: Formats values for logs, reports, or API responses.

### `appsec_scan_router.auth`
OAuth, local test login, session, CSRF, and encrypted credential storage support for the UI.

Constants: `SESSION_COOKIE_NAME`, `SESSION_TTL_SECONDS`, `OAUTH_STATE_TTL_SECONDS`, `PROVIDER_NAMES`, `TRUE_VALUES`

Classes:
- `AuthenticatedUser`: Class used by the application runtime or SDK contract.
  - `AuthenticatedUser.as_dict(self)`: Method that supports as dict behavior for its class.
- `SessionRecord`: Class used by the application runtime or SDK contract.
  - `SessionRecord.active(self, now=...)`: Method that supports active behavior for its class.
- `GitHubOAuthConfig`: Configuration object that carries validated runtime settings.
  - `GitHubOAuthConfig.from_env(cls)`: Method that supports from env behavior for its class.
  - `GitHubOAuthConfig.enabled(self)`: Method that supports enabled behavior for its class.
- `GoogleOAuthConfig`: Configuration object that carries validated runtime settings.
  - `GoogleOAuthConfig.from_env(cls)`: Method that supports from env behavior for its class.
  - `GoogleOAuthConfig.enabled(self)`: Method that supports enabled behavior for its class.
- `TestLoginConfig`: Configuration object that carries validated runtime settings.
  - `TestLoginConfig.from_env(cls)`: Method that supports from env behavior for its class.
  - `TestLoginConfig.user(self)`: Method that supports user behavior for its class.
- `CredentialStore`: State store used by authentication, sessions, or credentials.
  - `CredentialStore.encryption_key(self)`: Method that supports encryption key behavior for its class.
  - `CredentialStore.save_token(self, user_id, provider, token)`: Method that supports save token behavior for its class.
  - `CredentialStore.token(self, user_id, provider)`: Method that supports token behavior for its class.
  - `CredentialStore.delete_token(self, user_id, provider)`: Removes saved credentials or persisted values.
  - `CredentialStore.statuses(self, user_id)`: Method that supports statuses behavior for its class.
  - `CredentialStore.read_data(self)`: Reads request bodies or encrypted credential state.
  - `CredentialStore.write_data(self, data)`: Writes files, database rows, server events, or response payloads.
- `SessionStore`: State store used by authentication, sessions, or credentials.
  - `SessionStore.create(self, user)`: Creates schemas, clients, sessions, rows, or report structures.
  - `SessionStore.get(self, session_id)`: Retrieves a provider, HTTP, session, or report value.
  - `SessionStore.delete(self, session_id)`: Removes saved credentials or persisted values.
- `GitHubOAuthService`: Class used by the application runtime or SDK contract.
  - `GitHubOAuthService.enabled(self)`: Method that supports enabled behavior for its class.
  - `GitHubOAuthService.authorization_url(self, redirect_uri)`: Method that supports authorization url behavior for its class.
  - `GitHubOAuthService.complete(self, code, state, redirect_uri)`: Method that supports complete behavior for its class.
  - `GitHubOAuthService.exchange_code(self, code, redirect_uri)`: Exchanges an OAuth authorization code for an access token.
  - `GitHubOAuthService.fetch_user(self, access_token)`: Fetches repository content, commits, user profiles, or store pages.
  - `GitHubOAuthService.consume_state(self, state)`: Method that supports consume state behavior for its class.
  - `GitHubOAuthService.prune_states(self)`: Method that supports prune states behavior for its class.
- `GoogleOAuthService`: Class used by the application runtime or SDK contract.
  - `GoogleOAuthService.enabled(self)`: Method that supports enabled behavior for its class.
  - `GoogleOAuthService.authorization_url(self, redirect_uri)`: Method that supports authorization url behavior for its class.
  - `GoogleOAuthService.complete(self, code, state, redirect_uri)`: Method that supports complete behavior for its class.
  - `GoogleOAuthService.exchange_code(self, code, redirect_uri)`: Exchanges an OAuth authorization code for an access token.
  - `GoogleOAuthService.fetch_user(self, access_token)`: Fetches repository content, commits, user profiles, or store pages.
  - `GoogleOAuthService.consume_state(self, state)`: Method that supports consume state behavior for its class.
  - `GoogleOAuthService.prune_states(self)`: Method that supports prune states behavior for its class.
- `AuthManager`: Coordinator object that manages related runtime state.
  - `AuthManager.session(self, cookie_header)`: Creates, reads, or serializes session state.
  - `AuthManager.create_session(self, user)`: Creates schemas, clients, sessions, rows, or report structures.
  - `AuthManager.logout(self, session_id)`: Ends the active UI session.
  - `AuthManager.status(self, record)`: Returns current scan, store, database, or credential status.
  - `AuthManager.create_test_session(self)`: Creates schemas, clients, sessions, rows, or report structures.
  - `AuthManager.apply_credentials(self, payload, record)`: Method that supports apply credentials behavior for its class.
  - `AuthManager.delete_credential(self, provider, record)`: Removes saved credentials or persisted values.

Functions:
- `auth_state_dir(reports_root)`: Builds or evaluates authentication-related data.
- `env_value(*names)`: Reads environment variables or feature flags.
- `provider_name(value)`: Reads provider-specific token, project, or client values.
- `cookie_value(cookie_header, name)`: Builds or reads session cookie values.
- `session_cookie(session_id, secure=...)`: Creates, reads, or serializes session state.
- `expired_session_cookie(secure=...)`: Builds an expired session cookie header.
- `chmod_private(path, mode)`: Function that supports chmod private behavior.
- `utc_timestamp()`: Returns a UTC timestamp string.

### `appsec_scan_router.azure`
Azure DevOps API client used by the scanner without cloning repositories.

Constants: `LOGGER`

Classes:
- `AzureDevOpsClient`: Provider or external-service client that wraps network access and retries.
  - `AzureDevOpsClient.close(self)`: Releases open sessions, files, or listeners.
  - `AzureDevOpsClient.session(self)`: Creates, reads, or serializes session state.
  - `AzureDevOpsClient.get(self, path, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `AzureDevOpsClient.get_json(self, path, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `AzureDevOpsClient.get_text_or_content(self, path, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `AzureDevOpsClient.list_projects(self)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `AzureDevOpsClient.list_repos(self, project_name)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `AzureDevOpsClient.list_branches(self, project_name, repo_id)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `AzureDevOpsClient.list_build_definitions_for_repo(self, project_name, repo_id)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `AzureDevOpsClient.list_repo_items(self, project_name, repo_id, branch_name=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `AzureDevOpsClient.list_commits(self, project_name, repo_id, max_commits=..., page_size=..., branch_name=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `AzureDevOpsClient.fetch_file_content(self, project_name, repo_id, file_path, branch_name=...)`: Fetches repository content, commits, user profiles, or store pages.

Functions:
- `provider_connection_message(provider, url, exc)`: Reads provider-specific token, project, or client values.

### `appsec_scan_router.cli`
Command-line parser and executable entry point.

Functions:
- `parse_args(argv)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `validate_args(args, application_types, ado_org_pats)`: Function that supports validate args behavior.
- `provider_projects(args)`: Reads provider-specific token, project, or client values.
- `provider_token(args)`: Reads provider-specific token, project, or client values.
- `collect_ado_org_pats(args)`: Collects evidence, targets, metadata, or related values from input data.
- `collect_target_filters(args)`: Collects evidence, targets, metadata, or related values from input data.
- `provider_token_message(provider)`: Reads provider-specific token, project, or client values.
- `configure_logging(verbose)`: Configures runtime behavior such as logging.
- `env_value(*names)`: Reads environment variables or feature flags.
- `main(argv=...)`: Runs the module as a command-line entry point.

### `appsec_scan_router.constants`
Shared constants for defaults, categories, report columns, and inventory type labels.

Constants: `API_VERSION`, `DEFAULT_TIMEOUT_SECONDS`, `DEFAULT_MAX_WORKERS`, `DEFAULT_BRANCH_WORKERS`, `DEFAULT_CONTENT_WORKERS`, `DEFAULT_COMMIT_PAGE_SIZE`, `DEFAULT_BRANCH_AGE_DAYS`, `DEFAULT_STORE_COUNTRY`, `DEFAULT_STORE_TIMEOUT_SECONDS`, `DEFAULT_ACTIVITY_MODE`, `DEFAULT_OUT_PREFIX`, `DEFAULT_POSTGRES_SCHEMA`, `DEFAULT_POSTGRES_TABLE`, `DEFAULT_POSTGRES_HOST`, `DEFAULT_POSTGRES_PORT`, `DEFAULT_POSTGRES_DATABASE`, `DEFAULT_POSTGRES_USER`, `DEFAULT_POSTGRES_PASSWORD`, `MISSING_REQUESTS_MESSAGE`, `MISSING_PSYCOPG_MESSAGE`, `MISSING_CRYPTOGRAPHY_MESSAGE`, `FALLBACK_BRANCH_PRIORITY`, `ACTIVE_SHEET_NAME`, `OLDER_SHEET_NAME`, `KNOWN_CATEGORIES`, `CATEGORY_FIELDNAMES`, `KNOWN_INVENTORY_TYPES`, `TYPE_FIELDNAMES`, `APPLICATION_TYPE_LABELS`, `STORE_FIELDNAMES`, `CONTENT_FILES_TO_FETCH`, `CONTENT_FILE_SUFFIXES`, `CSV_FIELDNAMES`, `SCANNER_TARGET_FIELDNAMES`, `SONARQUBE_FIELDNAMES`

Functions:
- `active_sheet_name(branch_age_days=...)`: Function that supports active sheet name behavior.
- `older_sheet_name(branch_age_days=...)`: Function that supports older sheet name behavior.

### `appsec_scan_router.detection`
Evidence-based repository classification for mobile, web, API, middleware, AI, ML, and infrastructure assets.

Constants: `AI_LLM_DEPENDENCIES`, `AI_ORCHESTRATION_DEPENDENCIES`, `AI_ML_INFERENCE_DEPENDENCIES`, `AI_VECTOR_SEARCH_DEPENDENCIES`, `AI_SERVICE_DEPENDENCIES`, `AI_DEPENDENCY_RULES`, `AI_LLM_CONFIG_PATTERNS`, `AI_VECTOR_CONFIG_PATTERNS`, `AI_ML_CONFIG_PATTERNS`, `AI_CONTAINER_RUNTIME_TOKENS`

Functions:
- `detect_mobile_repo(paths, file_contents)`: Classifies a repository from paths and manifest evidence.
- `detect_inventory_repo(paths, file_contents)`: Classifies a repository from paths and manifest evidence.
- `collect_detection_evidence(paths, file_contents)`: Collects evidence, targets, metadata, or related values from input data.
- `collect_inventory_evidence(paths, file_contents)`: Collects evidence, targets, metadata, or related values from input data.
- `collect_path_evidence(path_set)`: Collects evidence, targets, metadata, or related values from input data.
- `collect_inventory_path_evidence(path_set)`: Collects evidence, targets, metadata, or related values from input data.
- `detect_android_manifest_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_gradle_evidence(path, content, properties=...)`: Classifies a repository from paths and manifest evidence.
- `detect_info_plist_evidence(path, content, properties=...)`: Classifies a repository from paths and manifest evidence.
- `detect_info_plist_strings_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_xcode_settings_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_pubspec_evidence(path, content, path_set)`: Classifies a repository from paths and manifest evidence.
- `detect_package_json_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_package_json_inventory_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_gradle_inventory_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_pom_inventory_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_python_inventory_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_go_mod_inventory_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_csproj_inventory_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_container_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_serverless_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_infrastructure_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_application_config_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `has_script(data, names)`: Function that supports has script behavior.
- `dependency_text_has_any(content, names)`: Function that supports dependency text has any behavior.
- `dependency_text_matches(content, names)`: Function that supports dependency text matches behavior.
- `detect_ai_dependency_name_evidence(path, dependency_names, source_label)`: Classifies a repository from paths and manifest evidence.
- `detect_ai_dependency_text_evidence(path, content, source_label)`: Classifies a repository from paths and manifest evidence.
- `collect_ai_dependency_evidence(path, source_label, matcher)`: Collects evidence, targets, metadata, or related values from input data.
- `ai_capability_evidence(path, category, detail, weight)`: Function that supports ai capability evidence behavior.
- `format_matches(matches)`: Formats values for logs, reports, or API responses.
- `detect_expo_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_expo_dynamic_config_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_capacitor_json_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_capacitor_ts_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_cordova_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_csproj_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_pipeline_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `dedupe_evidence(evidence)`: Function that supports dedupe evidence behavior.

### `appsec_scan_router.entrypoint`
Container entry point that dispatches UI or CLI modes.

Functions:
- `main()`: Runs the module as a command-line entry point.
- `exec_module(module, args)`: Function that supports exec module behavior.
- `exec_callable(module, function, args)`: Function that supports exec callable behavior.

### `appsec_scan_router.github`
GitHub Enterprise API client and URL normalization utilities.

Constants: `LOGGER`, `GITHUB_DEPLOYMENT_ENVIRONMENTS`, `GITHUB_SUCCESSFUL_DEPLOYMENT_STATES`

Classes:
- `GitHubEnterpriseClient`: Provider or external-service client that wraps network access and retries.
  - `GitHubEnterpriseClient.close(self)`: Releases open sessions, files, or listeners.
  - `GitHubEnterpriseClient.session(self)`: Creates, reads, or serializes session state.
  - `GitHubEnterpriseClient.get(self, url, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `GitHubEnterpriseClient.get_json(self, path, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `GitHubEnterpriseClient.list_projects(self)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.list_repos(self, project_name)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.repo_from_api(self, repo)`: Method that supports repo from api behavior for its class.
  - `GitHubEnterpriseClient.list_branches(self, project_name, repo_id)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.list_build_definitions_for_repo(self, project_name, repo_id)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.deployment_is_successful(self, repo_id, deployment)`: Method that supports deployment is successful behavior for its class.
  - `GitHubEnterpriseClient.list_repo_items(self, project_name, repo_id, branch_name=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.tree_ref_for_branch(self, repo_id, branch_name)`: Method that supports tree ref for branch behavior for its class.
  - `GitHubEnterpriseClient.list_commits(self, project_name, repo_id, max_commits=..., page_size=..., branch_name=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.fetch_file_content(self, project_name, repo_id, file_path, branch_name=...)`: Fetches repository content, commits, user profiles, or store pages.

Functions:
- `github_commit_to_activity_commit(commit)`: Handles GitHub Enterprise provider behavior.
- `normalize_github_api_url(base_url)`: Normalizes input into the canonical representation used by the scanner.
- `insecure_provider_urls_allowed()`: Function that supports insecure provider urls allowed behavior.
- `allowed_github_hosts()`: Function that supports allowed github hosts behavior.
- `env_flag(*names)`: Reads environment variables or feature flags.

### `appsec_scan_router.metadata`
Manifest parsers for mobile application name, version, and app identifier metadata.

Functions:
- `extract_mobile_metadata(file_contents)`: Extracts structured metadata from manifests, commits, or report rows.
- `collect_metadata_properties(file_contents)`: Collects evidence, targets, metadata, or related values from input data.
- `parse_properties_file(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_xcode_settings(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_msbuild_properties(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `resolve_property_value(value, properties)`: Resolves placeholders or labels to concrete values.
- `parse_info_plist(content, properties=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_plist_like_text(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_info_plist_strings(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `apple_strings_value(content, key)`: Reads Apple-specific metadata or lookup values.
- `parse_xcode_settings_metadata(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `xcode_setting_value(content, key)`: Function that supports xcode setting value behavior.
- `collect_android_strings(file_contents)`: Collects evidence, targets, metadata, or related values from input data.
- `parse_android_manifest(content, string_resources=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `resolve_android_label(label, string_resources)`: Resolves placeholders or labels to concrete values.
- `parse_capacitor_json(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_capacitor_ts(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_cordova_config(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_expo_config(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_expo_dynamic_config(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_gradle_metadata(content, properties=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `gradle_assignment_value(content, key)`: Function that supports gradle assignment value behavior.
- `parse_pubspec(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_package_json(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_csproj(content, properties=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_msbuild_props(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.

### `appsec_scan_router.models`
Dataclasses and exceptions that define scanner contracts.

Classes:
- `AzureDevOpsError`: Exception type used to preserve provider-specific error details.
- `AzureDevOpsOrgPat`: Class used by the application runtime or SDK contract.
- `SourceTargetFilter`: Class used by the application runtime or SDK contract.
- `ScanConfig`: Configuration object that carries validated runtime settings.
- `RepoScanTarget`: Class used by the application runtime or SDK contract.
- `BranchScanTarget`: Class used by the application runtime or SDK contract.
- `MobileAppMetadata`: Dataclass that carries extracted metadata between scanner stages.
- `RepoActivityMetadata`: Dataclass that carries extracted metadata between scanner stages.
- `StoreListing`: Class used by the application runtime or SDK contract.
- `DetectionEvidence`: Class used by the application runtime or SDK contract.
  - `DetectionEvidence.as_dict(self)`: Method that supports as dict behavior for its class.

### `appsec_scan_router.org_tokens`
Parser and serializer for multi-organization Azure DevOps PAT configuration.

Functions:
- `parse_ado_org_pat_values(values)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_ado_org_pat_value(value)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_ado_org_pat_sequence(values)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `split_ado_org_pat_text(text)`: Splits delimited configuration text into entries.
- `make_ado_org_pat(org, pat)`: Constructs a validated dataclass or parsed object.
- `ado_org_pats_to_json(org_pats)`: Function that supports ado org pats to json behavior.

### `appsec_scan_router.postgres`
PostgreSQL schema creation, normalized upserts, status checks, and exports.

Constants: `CONTROL_CHARACTER_RE`, `SQL_NAME_RE`, `NORMALIZED_TABLES`, `EXPORT_COLUMNS`, `PRIMARY_KEY_COLUMNS`, `POSTGRES_COLUMNS`, `FLAT_TABLE_MIGRATIONS`

Classes:
- `PostgresInventoryWriter`: Context-managed writer that streams results to reports or storage.
  - `PostgresInventoryWriter.__enter__(self)`: Opens the context-managed resource and returns it for use.
  - `PostgresInventoryWriter.__exit__(self, exc_type, exc_value, traceback)`: Closes the context-managed resource when the block exits.
  - `PostgresInventoryWriter.close(self)`: Releases open sessions, files, or listeners.
  - `PostgresInventoryWriter.write_result(self, result)`: Writes files, database rows, server events, or response payloads.
  - `PostgresInventoryWriter.create_schema(self)`: Creates schemas, clients, sessions, rows, or report structures.
  - `PostgresInventoryWriter.write_flat_result(self, result)`: Writes files, database rows, server events, or response payloads.
  - `PostgresInventoryWriter.write_normalized_result(self, result)`: Writes files, database rows, server events, or response payloads.
  - `PostgresInventoryWriter.upsert_scan_run(self, result)`: Inserts or updates normalized PostgreSQL rows.
  - `PostgresInventoryWriter.upsert_repository(self, result)`: Inserts or updates normalized PostgreSQL rows.
  - `PostgresInventoryWriter.upsert_branch_inventory(self, repository_id, result)`: Inserts or updates normalized PostgreSQL rows.
  - `PostgresInventoryWriter.replace_value_set(self, table_name, column_name, branch_inventory_id, values)`: Replaces normalized database child rows for a branch inventory item.
  - `PostgresInventoryWriter.replace_store_listings(self, branch_inventory_id, result)`: Replaces normalized database child rows for a branch inventory item.
  - `PostgresInventoryWriter.upsert_sql(self)`: Inserts or updates normalized PostgreSQL rows.
  - `PostgresInventoryWriter.row_values(self, result)`: Builds database or report row values.

Functions:
- `create_database_schema(connection, schema, flat_table)`: Creates schemas, clients, sessions, rows, or report structures.
- `create_flat_table(connection, schema, table)`: Creates schemas, clients, sessions, rows, or report structures.
- `create_normalized_tables(connection, schema)`: Creates schemas, clients, sessions, rows, or report structures.
- `create_export_view(connection, schema)`: Creates schemas, clients, sessions, rows, or report structures.
- `database_status(dsn, schema=..., table=..., owner_user_id=...)`: Reads, writes, exports, or reports PostgreSQL database state.
- `export_inventory_rows(dsn, schema=..., owner_user_id=..., limit=...)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `export_inventory_csv(dsn, schema=..., owner_user_id=..., limit=...)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `export_inventory_json(dsn, schema=..., owner_user_id=..., limit=...)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `normalized_row_count(connection, schema, owner_user_id)`: Function that supports normalized row count behavior.
- `flat_row_count(connection, schema, table, owner_user_id)`: Reads or writes the flat compatibility PostgreSQL table.
- `store_listing_rows(result)`: Looks up, validates, or reports app-store data.
- `schema_table_parts(schema, table)`: Function that supports schema table parts behavior.
- `table_identifier(table, schema=...)`: Builds safe PostgreSQL table identifiers.
- `object_identifier(schema, name)`: Builds safe PostgreSQL object identifiers.
- `sql_name(value, label)`: Function that supports sql name behavior.
- `index_name_prefix(table)`: Builds safe PostgreSQL index names.
- `text_value(value)`: Normalizes values for safe text output.
- `semicolon_values(value)`: Function that supports semicolon values behavior.
- `timestamp_value(value)`: Converts values into PostgreSQL timestamp-compatible strings.
- `int_value(value)`: Converts a value into an integer where possible.
- `bool_value(value)`: Converts a value into a boolean representation.
- `json_value(value)`: Normalizes or exports JSON-compatible values.
- `postgres_json_value(value)`: Builds PostgreSQL DSNs or configuration values.
- `export_cell(value)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `postgres_error_message(error)`: Builds PostgreSQL DSNs or configuration values.

### `appsec_scan_router.reports`
Streaming CSV, JSON, XLSX, Semgrep, SonarQube, and generic scanner-target report writers.

Constants: `WORKBOOK_COLUMN_WIDTHS`

Classes:
- `StreamingReportWriter`: Context-managed writer that streams results to reports or storage.
  - `StreamingReportWriter.__enter__(self)`: Opens the context-managed resource and returns it for use.
  - `StreamingReportWriter.__exit__(self, exc_type, exc_value, traceback)`: Closes the context-managed resource when the block exits.
  - `StreamingReportWriter.write_result(self, result)`: Writes files, database rows, server events, or response payloads.
  - `StreamingReportWriter.flush(self)`: Method that supports flush behavior for its class.
  - `StreamingReportWriter.close(self)`: Releases open sessions, files, or listeners.

Functions:
- `write_outputs(results, out_dir, out_prefix, branch_age_days=...)`: Writes files, database rows, server events, or response payloads.
- `scanner_target_row(result)`: Builds scanner target references or rows.
- `sonarqube_project_row(result)`: Function that supports sonarqube project row behavior.
- `workbook_cell_value(value)`: Formats values for Excel workbook output.

### `appsec_scan_router.scanner`
Core orchestration for provider discovery, branch resolution, content fetching, detection, enrichment, and report/database output.

Constants: `LOGGER`

Functions:
- `scan_to_reports(config)`: Runs or coordinates repository and branch scanning.
- `scan(config, on_result=...)`: Runs or coordinates repository and branch scanning.
- `scan_single_org(config, on_result=...)`: Runs or coordinates repository and branch scanning.
- `create_source_client(config)`: Creates schemas, clients, sessions, rows, or report structures.
- `drain_branch_scans(pending_branch_scans, results, on_result, block)`: Consumes completed asynchronous branch scan work.
- `handle_branch_scan_future(future, on_result)`: Handles a UI HTTP route or asynchronous scan result.
- `scan_branch_target(client, target, content_executor, min_confidence_rank, max_commits_per_repo, branch_age_days, activity_mode, store_client, application_types=...)`: Runs or coordinates repository and branch scanning.
- `scan_repo(client, target, content_executor, min_confidence_rank, max_commits_per_repo, branch_age_days, store_client, activity_mode=..., application_types=...)`: Runs or coordinates repository and branch scanning.
- `list_branch_targets(client, target)`: Lists provider resources such as projects, repositories, branches, or commits.
- `scan_branch(client, target, branch_name, content_executor, min_confidence_rank, max_commits_per_repo, branch_age_days, activity_mode, store_client, application_types=...)`: Runs or coordinates repository and branch scanning.
- `build_scan_row(target, branch_name, metadata, contents, paths, activity, confidence, score, categories, evidence, branch_age_days, store_client)`: Builds a command, URL, row, payload, or configuration object.
- `row_sort_key(row)`: Builds database or report row values.
- `log_detected_result(result)`: Function that supports log detected result behavior.
- `create_store_client(config)`: Creates schemas, clients, sessions, rows, or report structures.
- `branch_name_from_ref(ref_name)`: Computes branch metadata, branch selection, or branch report values.
- `default_branch_name_from_repo(repo)`: Returns a default value derived from configuration or source metadata.
- `fallback_branch_name(client, target)`: Chooses fallback branch values when default branch metadata is unavailable.
- `pipeline_fallback_branch_name(client, target, branch_names)`: Resolves branch metadata from CI/CD pipeline definitions.
- `branch_names_from_refs(refs)`: Computes branch metadata, branch selection, or branch report values.
- `branch_names_from_build_definitions(definitions)`: Computes branch metadata, branch selection, or branch report values.
- `extract_branch_values(values)`: Extracts structured metadata from manifests, commits, or report rows.
- `select_pipeline_branch_name(branch_names, pipeline_branch_names)`: Selects branch or UI target values from candidates.
- `select_fallback_branch_name(branch_names)`: Selects branch or UI target values from candidates.
- `branch_deployment_score(branch_name)`: Computes branch metadata, branch selection, or branch report values.
- `is_direct_deployment_branch_name(branch_name)`: Evaluates a predicate used by detection, validation, or UI flow.
- `branch_name_match_keys(branch_name)`: Computes branch metadata, branch selection, or branch report values.
- `normalized_branch_key(value)`: Function that supports normalized branch key behavior.
- `branch_age_bucket(last_updated, branch_age_days, now=...)`: Computes branch metadata, branch selection, or branch report values.
- `identifier_status(identifier)`: Builds or validates mobile/application identifier values.
- `category_columns(categories)`: Builds category-specific report columns.
- `type_columns(inventory_types)`: Builds inventory type report columns.
- `inventory_types_from_categories(categories)`: Builds inventory names, versions, types, or report fields.
- `normalize_application_types(application_types)`: Normalizes input into the canonical representation used by the scanner.
- `inventory_type_matches(inventory_types, application_types)`: Builds inventory names, versions, types, or report fields.
- `store_lookup_allowed(application_types)`: Looks up, validates, or reports app-store data.
- `log_scan_progress(repositories_prepared, repositories_total, branches_scanned, branches_total)`: Function that supports log scan progress behavior.
- `repo_source_url(repo)`: Function that supports repo source url behavior.
- `scanner_target_ref(source_url, branch_name)`: Builds scanner target references or rows.
- `sonar_project_key(project_name, repo_name, branch_name)`: Builds SonarQube project identifiers or rows.
- `inventory_name_from_metadata(metadata, contents, repo_name)`: Builds inventory names, versions, types, or report fields.
- `inventory_version_from_metadata(metadata, contents)`: Builds inventory names, versions, types, or report fields.
- `primary_language_for_branch(contents, paths, categories)`: Determines the primary language or key report value.
- `package_json_language(contents)`: Function that supports package json language behavior.
- `merged_package_dependency_names(contents)`: Merges dependency maps into a single dependency set.
- `first_manifest_value(*values)`: Returns the first usable value from a sequence.
- `package_json_value(contents, key)`: Function that supports package json value behavior.
- `pyproject_value(contents, key)`: Function that supports pyproject value behavior.
- `pom_xml_value(contents, tag_name)`: Function that supports pom xml value behavior.
- `csproj_value(contents, tag_name)`: Function that supports csproj value behavior.
- `pubspec_value(contents, key)`: Function that supports pubspec value behavior.
- `fetch_repo_activity(client, project_name, repo_id, branch_name, max_commits, activity_mode)`: Fetches repository content, commits, user profiles, or store pages.
- `fetch_contents(client, project_name, repo_id, branch_name, paths, executor)`: Fetches repository content, commits, user profiles, or store pages.
- `collect_targets(client, project_name, target_filters=...)`: Collects evidence, targets, metadata, or related values from input data.
- `source_organization(client)`: Builds provider target filters or target labels.
- `selected_project_names(organization, project_name, target_filters=...)`: Function that supports selected project names behavior.
- `target_filters_for_source(target_filters, organization)`: Builds or filters provider scan targets.
- `target_filter_matches_source(filter_org, organization)`: Builds or filters provider scan targets.
- `dedupe_values(values)`: Function that supports dedupe values behavior.
- `iter_completed_branch_target_lists(repo_executor, client, targets, max_in_flight)`: Yields completed asynchronous work items.
- `iter_completed_repo_scans(repo_executor, client, targets, content_executor, max_in_flight, min_confidence_rank, max_commits_per_repo, branch_age_days, store_client, activity_mode=..., application_types=...)`: Yields completed asynchronous work items.

### `appsec_scan_router.sdk`
Small callable SDK wrapper around scanner configuration and execution.

Classes:
- `ApplicationInventoryService`: Class used by the application runtime or SDK contract.
  - `ApplicationInventoryService.scan(self, on_result=...)`: Runs or coordinates repository and branch scanning.
  - `ApplicationInventoryService.scan_to_reports(self)`: Runs or coordinates repository and branch scanning.

### `appsec_scan_router.store_lookup`
Apple App Store and Google Play lookup and validation helpers.

Constants: `LOGGER`, `APPLE_PLATFORM`, `GOOGLE_PLATFORM`, `APPLE_DISPLAY_NAME`, `GOOGLE_DISPLAY_NAME`, `CROSS_PLATFORM_CATEGORIES`, `BOTH_STORE_PLATFORMS`, `STORE_IDENTIFIER_PATTERN`

Classes:
- `StoreLookupClient`: Provider or external-service client that wraps network access and retries.
  - `StoreLookupClient.session(self)`: Creates, reads, or serializes session state.
  - `StoreLookupClient.close(self)`: Releases open sessions, files, or listeners.
  - `StoreLookupClient.lookup(self, identifier, categories)`: Method that supports lookup behavior for its class.
  - `StoreLookupClient.lookup_platform(self, platform, identifier)`: Method that supports lookup platform behavior for its class.
  - `StoreLookupClient.lookup_apple_app_store(self, identifier)`: Method that supports lookup apple app store behavior for its class.
  - `StoreLookupClient.lookup_google_play(self, identifier)`: Method that supports lookup google play behavior for its class.
- `MetaTagParser`: Class used by the application runtime or SDK contract.
  - `MetaTagParser.handle_starttag(self, tag, attrs)`: Handles a UI HTTP route or asynchronous scan result.
  - `MetaTagParser.handle_endtag(self, tag)`: Handles a UI HTTP route or asynchronous scan result.
  - `MetaTagParser.handle_data(self, data)`: Handles a UI HTTP route or asynchronous scan result.

Functions:
- `target_store_platforms(categories)`: Builds or filters provider scan targets.
- `store_columns(identifier, categories, store_client)`: Looks up, validates, or reports app-store data.
- `disabled_store_listings()`: Builds disabled or unavailable store lookup values.
- `identifier_missing_store_listings(categories)`: Builds or validates mobile/application identifier values.
- `invalid_identifier_store_listings(categories, identifier)`: Function that supports invalid identifier store listings behavior.
- `is_store_identifier_candidate(identifier)`: Evaluates a predicate used by detection, validation, or UI flow.
- `store_columns_from_listings(listings)`: Looks up, validates, or reports app-store data.
- `listing_column_values(platform, listing)`: Function that supports listing column values behavior.
- `store_validation_result(listings)`: Looks up, validates, or reports app-store data.
- `listing_validation_result(listing)`: Function that supports listing validation result behavior.
- `boolean_text(value)`: Converts a value into a boolean representation.
- `aggregate_store_status(listings)`: Aggregates lower-level values into a report-ready status.
- `display_name_for_platform(platform)`: Formats a user-facing label.
- `normalize_google_play_title(title)`: Normalizes input into the canonical representation used by the scanner.
- `google_play_not_found_text(text)`: Handles Google or Google Play provider behavior.
- `google_play_app_page(meta, title, identifier)`: Handles Google or Google Play provider behavior.
- `extract_google_play_version(text)`: Extracts structured metadata from manifests, commits, or report rows.
- `extract_google_play_updated(text)`: Extracts structured metadata from manifests, commits, or report rows.
- `regex_store_value(text, pattern)`: Function that supports regex store value behavior.
- `google_play_url(identifier, country)`: Handles Google or Google Play provider behavior.

### `appsec_scan_router.target_filters`
Parser and serializer for selected Azure DevOps projects and GitHub repositories.

Functions:
- `parse_source_target_filter_values(values)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_source_target_filter_value(value)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_source_target_filter_sequence(values)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `split_source_target_filter_text(text)`: Splits delimited configuration text into entries.
- `make_source_target_filter(org, project)`: Constructs a validated dataclass or parsed object.
- `source_target_filters_to_json(target_filters)`: Builds provider target filters or target labels.
- `target_filter_value(target_filter)`: Builds or filters provider scan targets.

### `appsec_scan_router.ui`
HTTP UI server, scan manager, request handlers, progress parsing, and UI configuration normalization.

Constants: `DEFAULT_UI_HOST`, `DEFAULT_UI_PORT`, `MAX_LOG_LINES`, `DEFAULT_MAX_JSON_BODY_BYTES`, `REPORT_EXTENSIONS`, `SCAN_STATUSES_DONE`, `BRANCH_PROGRESS_PATTERN`, `REPO_PROGRESS_PATTERN`, `TARGET_COUNT_PATTERN`, `SCAN_PROGRESS_PATTERN`, `HOST_HEADER_RE`, `SAFE_CHILD_ENV_KEYS`, `SECURITY_HEADER_VALUES`

Classes:
- `ScanRun`: Class used by the application runtime or SDK contract.
  - `ScanRun.append_log(self, line)`: Method that supports append log behavior for its class.
  - `ScanRun.set_status(self, status, exit_code=...)`: Method that supports set status behavior for its class.
  - `ScanRun.publish(self, event, data)`: Method that supports publish behavior for its class.
  - `ScanRun.add_listener(self)`: Adds an item to the current in-memory collection or UI state.
  - `ScanRun.remove_listener(self, listener)`: Removes an item from UI state or listener collections.
  - `ScanRun.close_listeners(self)`: Releases open sessions, files, or listeners.
  - `ScanRun.report_files(self)`: Builds report metadata or content types.
  - `ScanRun.summary(self)`: Method that supports summary behavior for its class.
- `ScanManager`: Coordinator object that manages related runtime state.
  - `ScanManager.list_scans(self, owner_user_id=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `ScanManager.get_scan(self, scan_id)`: Retrieves a provider, HTTP, session, or report value.
  - `ScanManager.start_scan(self, config)`: Starts a scan or sign-in flow.
  - `ScanManager.stop_scan(self, scan_id)`: Stops an active scan process.
- `ApplicationInventoryServiceHandler`: HTTP request handler for the web UI.
  - `ApplicationInventoryServiceHandler.do_GET(self)`: Handles HTTP G requests for the UI server.
  - `ApplicationInventoryServiceHandler.do_POST(self)`: Handles HTTP P requests for the UI server.
  - `ApplicationInventoryServiceHandler.handle_static(self, path)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_scan_get(self, path)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_start_scan(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_github_auth_start(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_github_auth_callback(self, query)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_google_auth_start(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_google_auth_callback(self, query)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_test_auth_start(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_logout(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_delete_credential(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_database_status(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_database_export(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.handle_source_targets(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.send_static(self, name, content_type)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.send_report(self, run, filename)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.stream_scan_events(self, run)`: Streams server-sent scan events to the browser.
  - `ApplicationInventoryServiceHandler.write_event(self, event, data)`: Writes files, database rows, server events, or response payloads.
  - `ApplicationInventoryServiceHandler.read_json(self)`: Reads request bodies or encrypted credential state.
  - `ApplicationInventoryServiceHandler.send_json(self, payload, status=..., headers=...)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.send_bytes(self, content, content_type, status=..., headers=...)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.log_message(self, format, *args)`: Method that supports log message behavior for its class.
  - `ApplicationInventoryServiceHandler.redirect(self, location, cookie=...)`: Method that supports redirect behavior for its class.
  - `ApplicationInventoryServiceHandler.end_headers(self)`: Method that supports end headers behavior for its class.
  - `ApplicationInventoryServiceHandler.current_session(self)`: Returns the current request/session state.
  - `ApplicationInventoryServiceHandler.require_session(self)`: Requires a valid authenticated session before continuing.
  - `ApplicationInventoryServiceHandler.valid_csrf(self, record)`: Validates session or request state.
  - `ApplicationInventoryServiceHandler.redirect_uri(self, provider)`: Method that supports redirect uri behavior for its class.

Functions:
- `normalize_scan_config(config)`: Normalizes input into the canonical representation used by the scanner.
- `normalize_database_config(config)`: Normalizes input into the canonical representation used by the scanner.
- `discover_source_targets(config)`: Discovers source targets from provider APIs.
- `discover_azure_targets(config, timeout)`: Discovers source targets from provider APIs.
- `discover_github_targets(config, timeout)`: Discovers source targets from provider APIs.
- `discovery_token(config, provider)`: Function that supports discovery token behavior.
- `source_target(provider, org, project, kind, display_name=...)`: Builds provider target filters or target labels.
- `sorted_targets(targets)`: Sorts values into deterministic report order.
- `build_scan_command(config, reports_dir)`: Builds a command, URL, row, payload, or configuration object.
- `scan_target_summary(config)`: Runs or coordinates repository and branch scanning.
- `redact_command(command)`: Removes sensitive values from displayed commands.
- `scan_environment(config)`: Runs or coordinates repository and branch scanning.
- `scan_progress(logs, started_at, ended_at, status)`: Runs or coordinates repository and branch scanning.
- `progress_percent(repo_done, repo_total, branch_done, branch_total)`: Computes progress percentages or ETA values.
- `bounded_ratio(done, total)`: Constrains a numeric ratio to a safe range.
- `estimated_remaining_seconds(started_at, percent)`: Estimates remaining scan time from progress data.
- `parse_iso_datetime(value)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `default_ui_config(reports_root)`: Returns a default value derived from configuration or source metadata.
- `report_content_type(path)`: Builds report metadata or content types.
- `new_scan_id()`: Creates a new generated identifier.
- `clean_text(value)`: Normalizes text by trimming, removing placeholders, or rejecting unresolved values.
- `env_value(*names)`: Reads environment variables or feature flags.
- `env_flag(*names)`: Reads environment variables or feature flags.
- `max_json_body_bytes()`: Computes a maximum configured value.
- `base_process_environment()`: Builds a base environment or base URL value.
- `inherit_secret(env, name)`: Copies an approved secret into a child scan process environment.
- `security_headers()`: Builds HTTP security headers.
- `attachment_header(filename)`: Builds a safe attachment response header.
- `safe_public_url(value)`: Validates and sanitizes URLs, headers, prefixes, or file names.
- `safe_request_base_url(proto, host)`: Validates and sanitizes URLs, headers, prefixes, or file names.
- `database_export_error(error)`: Reads, writes, exports, or reports PostgreSQL database state.
- `first_query_value(params, name)`: Returns the first usable value from a sequence.
- `owner_scope(record)`: Reads owner scoping values for user-isolated scans.
- `owner_login(record)`: Reads owner scoping values for user-isolated scans.
- `run_owner_id(run)`: Function that supports run owner id behavior.
- `ado_org_summary(org_pats)`: Function that supports ado org summary behavior.
- `clean_choice(value, allowed, default)`: Normalizes text by trimming, removing placeholders, or rejecting unresolved values.
- `safe_prefix(value)`: Validates and sanitizes URLs, headers, prefixes, or file names.
- `normalize_ui_application_types(value)`: Normalizes input into the canonical representation used by the scanner.
- `postgres_dsn_from_config(config)`: Builds PostgreSQL DSNs or configuration values.
- `positive_int(value, default)`: Parses a positive integer with a default fallback.
- `nonnegative_int(value, default)`: Parses a non-negative integer with a default fallback.
- `utc_now()`: Returns a UTC timestamp string.
- `secure_cookie()`: Function that supports secure cookie behavior.
- `serve(host, port, reports_dir)`: Runs the web UI server.
- `parse_args(argv)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `main(argv=...)`: Runs the module as a command-line entry point.

### `appsec_scan_router.utils`
Shared parsing, cleanup, YAML/XML/JSON, version, and confidence helpers.

Functions:
- `should_fetch_content(path)`: Decides whether content should be fetched or processed.
- `normalize_path(path)`: Normalizes input into the canonical representation used by the scanner.
- `first_present(values)`: Returns the first usable value from a sequence.
- `clean_value(value)`: Normalizes text by trimming, removing placeholders, or rejecting unresolved values.
- `clean_value_without_resource_filter(value)`: Normalizes text by trimming, removing placeholders, or rejecting unresolved values.
- `clean_version(value)`: Normalizes text by trimming, removing placeholders, or rejecting unresolved values.
- `load_json_object(content)`: Loads state or source data from disk, HTTP, or form input.
- `merged_package_dependencies(data)`: Merges dependency maps into a single dependency set.
- `yaml_has_flutter_dependency(content)`: Reads YAML-like scalar values used by lightweight manifest parsing.
- `yaml_scalar(content, key)`: Reads YAML-like scalar values used by lightweight manifest parsing.
- `xml_text(content, tag_name)`: Function that supports xml text behavior.
- `regex_value(content, pattern)`: Function that supports regex value behavior.
- `confidence_rank(confidence)`: Function that supports confidence rank behavior.

## Browser UI Functions

### `appsec_scan_router/ui_static/app.js`
Browser-side controller for login, scan setup, progress monitoring, reports, database actions, and UI state.

Functions:
- `addAdoOrgPat()`: Adds an item to the current in-memory collection or UI state.
- `addSelectedTarget(target)`: Adds an item to the current in-memory collection or UI state.
- `applicationTypeLabel(type)`: Function that supports application type label behavior.
- `applicationTypesLabel(applicationTypes)`: Function that supports application types label behavior.
- `applyDefaultValues()`: Function that supports apply default values behavior.
- `authHeaders(jsonBody)`: Builds or evaluates authentication-related data.
- `authProviderName(provider)`: Builds or evaluates authentication-related data.
- `authProviders(session)`: Builds or evaluates authentication-related data.
- `bindEvents()`: Function that supports bind events behavior.
- `capitalize(text)`: Function that supports capitalize behavior.
- `checkDatabase()`: Checks current UI or provider state.
- `checkedValues(name)`: Function that supports checked values behavior.
- `clearDiscoveredTargets({silent = false} = {})`: Clears current UI state or selected values.
- `clearSelectedTargets()`: Clears current UI state or selected values.
- `closeEventSource()`: Releases open sessions, files, or listeners.
- `commitPendingAdoOrgPat({silent = false} = {})`: Function that supports commit pending ado org pat behavior.
- `copyCommand()`: Copies generated command text for the UI user.
- `databasePayload()`: Reads, writes, exports, or reports PostgreSQL database state.
- `downloadBlob(blob, filename)`: Downloads a client-side blob or log payload.
- `downloadLogs()`: Downloads a client-side blob or log payload.
- `durationText(totalSeconds)`: Function that supports duration text behavior.
- `escapeHtml(value)`: Function that supports escape html behavior.
- `exportDatabase(format)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `forgetSavedToken()`: Removes a saved provider token from UI state and encrypted storage.
- `formatBytes(value)`: Formats values for logs, reports, or API responses.
- `formatDate(value)`: Formats values for logs, reports, or API responses.
- `formPayload()`: Function that supports form payload behavior.
- `handleAdoOrgPatKeydown(event)`: Handles a UI HTTP route or asynchronous scan result.
- `handleSsoClick(event)`: Handles a UI HTTP route or asynchronous scan result.
- `isLoggedIn()`: Evaluates a predicate used by detection, validation, or UI flow.
- `listenToScan(scanId)`: Function that supports listen to scan behavior.
- `loadForm()`: Loads state or source data from disk, HTTP, or form input.
- `loadScans(preferredId = "")`: Loads state or source data from disk, HTTP, or form input.
- `loadSession()`: Loads state or source data from disk, HTTP, or form input.
- `loadSourceTargets()`: Loads state or source data from disk, HTTP, or form input.
- `logout()`: Ends the active UI session.
- `maskSecret(value)`: Masks a secret for display.
- `mergeScan(scan)`: Function that supports merge scan behavior.
- `normalizedTarget(target)`: Function that supports normalized target behavior.
- `notify(message)`: Function that supports notify behavior.
- `numberValue(data, name, fallback)`: Function that supports number value behavior.
- `pluralize(noun, count)`: Function that supports pluralize behavior.
- `providerLabel(provider)`: Reads provider-specific token, project, or client values.
- `providerTargetNoun()`: Reads provider-specific token, project, or client values.
- `removeAdoOrgPat(org)`: Removes an item from UI state or listener collections.
- `removeSelectedTarget(target)`: Removes an item from UI state or listener collections.
- `renderActiveScan()`: Renders UI state into the browser DOM.
- `renderAdoOrgPatList()`: Renders UI state into the browser DOM.
- `renderAll()`: Renders UI state into the browser DOM.
- `renderAuth()`: Renders UI state into the browser DOM.
- `renderDatabaseStatus()`: Renders UI state into the browser DOM.
- `renderLogs()`: Renders UI state into the browser DOM.
- `renderReports()`: Renders UI state into the browser DOM.
- `renderRuns()`: Renders UI state into the browser DOM.
- `renderShell()`: Renders UI state into the browser DOM.
- `renderSsoOption(link, statusElement, provider, label)`: Renders UI state into the browser DOM.
- `renderTargetFilters()`: Renders UI state into the browser DOM.
- `renderTargetWarnings()`: Renders UI state into the browser DOM.
- `resetDefaults()`: Function that supports reset defaults behavior.
- `saveForm()`: Function that supports save form behavior.
- `scanEta(scan)`: Runs or coordinates repository and branch scanning.
- `scanPercent(scan)`: Runs or coordinates repository and branch scanning.
- `scanProgress(scan)`: Runs or coordinates repository and branch scanning.
- `scanProgressDetail(scan)`: Runs or coordinates repository and branch scanning.
- `scanRuntime(scan)`: Runs or coordinates repository and branch scanning.
- `selectScan(scan, connect = true)`: Selects branch or UI target values from candidates.
- `selectVisibleTargets()`: Selects branch or UI target values from candidates.
- `setActiveView(viewId)`: Function that supports set active view behavior.
- `setBusy(isBusy)`: Function that supports set busy behavior.
- `setCheckboxGroup(name, values)`: Function that supports set checkbox group behavior.
- `setDatabaseBusy(isBusy)`: Function that supports set database busy behavior.
- `setTargetBusy(isBusy)`: Function that supports set target busy behavior.
- `showAuthResult()`: Function that supports show auth result behavior.
- `sourceFieldChanged(target)`: Builds provider target filters or target labels.
- `sourcePayload()`: Builds provider target filters or target labels.
- `startScan()`: Starts a scan or sign-in flow.
- `stopScan()`: Stops an active scan process.
- `syncAdoOrgPatInput()`: Synchronizes UI form state with hidden serialized fields.
- `syncCredentialFields()`: Synchronizes UI form state with hidden serialized fields.
- `syncDatabaseFields()`: Synchronizes UI form state with hidden serialized fields.
- `syncMobileOptions()`: Synchronizes UI form state with hidden serialized fields.
- `syncProviderFields()`: Synchronizes UI form state with hidden serialized fields.
- `syncTargetFilterInput()`: Synchronizes UI form state with hidden serialized fields.
- `targetFilterPayload()`: Builds or filters provider scan targets.
- `targetKey(target)`: Builds or filters provider scan targets.
- `targetLabel(target)`: Builds or filters provider scan targets.
- `targetMeta(target)`: Builds or filters provider scan targets.
- `tick()`: Function that supports tick behavior.
- `toggleToken()`: Toggles UI state such as token visibility.
- `value(data, name)`: Function that supports value behavior.
- `visibleTargets()`: Returns currently visible UI targets.
