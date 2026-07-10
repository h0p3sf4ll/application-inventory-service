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
- `developer_identity_key(person, fallback)`: Helper for developer identity key.
- `parse_ado_datetime(value)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `format_ado_datetime(value)`: Formats values for logs, reports, or API responses.

### `appsec_scan_router.auth`
OAuth, local test login, session, CSRF, and encrypted credential storage support for the UI.

Constants: `SESSION_COOKIE_NAME`, `SESSION_TTL_SECONDS`, `OAUTH_STATE_TTL_SECONDS`, `PROVIDER_NAMES`, `TRUE_VALUES`

Classes:
- `AuthenticatedUser`: Runtime data object.
  - `AuthenticatedUser.as_dict(self)`: Implements as dict behavior.
- `SessionRecord`: Runtime data object.
  - `SessionRecord.active(self, now=...)`: Implements active behavior.
- `GitHubOAuthConfig`: Configuration object that carries validated runtime settings.
  - `GitHubOAuthConfig.from_env(cls)`: Implements from env behavior.
  - `GitHubOAuthConfig.enabled(self)`: Implements enabled behavior.
- `GitHubEnterpriseOAuthConfig`: GitHub Enterprise OAuth endpoints, client settings, and scopes resolved from environment variables.
  - `GitHubEnterpriseOAuthConfig.from_env(cls)`: Resolves the Enterprise OAuth configuration.
  - `GitHubEnterpriseOAuthConfig.enabled(self)`: Confirms that the client and all OAuth endpoints are configured.
- `GoogleOAuthConfig`: Configuration object that carries validated runtime settings.
  - `GoogleOAuthConfig.from_env(cls)`: Implements from env behavior.
  - `GoogleOAuthConfig.enabled(self)`: Implements enabled behavior.
- `TestLoginConfig`: Configuration object that carries validated runtime settings.
  - `TestLoginConfig.from_env(cls)`: Implements from env behavior.
  - `TestLoginConfig.user(self)`: Implements user behavior.
- `CredentialStore`: State store used by authentication, sessions, or credentials.
  - `CredentialStore.encryption_key(self)`: Implements encryption key behavior.
  - `CredentialStore.save_token(self, user_id, provider, token)`: Implements save token behavior.
  - `CredentialStore.token(self, user_id, provider)`: Implements token behavior.
  - `CredentialStore.delete_token(self, user_id, provider)`: Removes saved credentials or persisted values.
  - `CredentialStore.statuses(self, user_id)`: Implements statuses behavior.
  - `CredentialStore.read_data(self)`: Reads request bodies or encrypted credential state.
  - `CredentialStore.write_data(self, data)`: Writes files, database rows, server events, or response payloads.
- `SessionStore`: State store used by authentication, sessions, or credentials.
  - `SessionStore.create(self, user)`: Creates schemas, clients, sessions, rows, or report structures.
  - `SessionStore.get(self, session_id)`: Retrieves a provider, HTTP, session, or report value.
  - `SessionStore.delete(self, session_id)`: Removes saved credentials or persisted values.
- `GitHubOAuthService`: Runtime data object.
  - `GitHubOAuthService.enabled(self)`: Implements enabled behavior.
  - `GitHubOAuthService.authorization_url(self, redirect_uri)`: Implements authorization url behavior.
  - `GitHubOAuthService.complete(self, code, state, redirect_uri)`: Implements complete behavior.
  - `GitHubOAuthService.complete_with_token(self, code, state, redirect_uri)`: Completes OAuth and returns the user with the access token for encrypted storage.
  - `GitHubOAuthService.exchange_code(self, code, redirect_uri)`: Exchanges an OAuth authorization code for an access token.
  - `GitHubOAuthService.fetch_user(self, access_token)`: Fetches repository content, commits, user profiles, or store pages.
  - `GitHubOAuthService.consume_state(self, state)`: Implements consume state behavior.
  - `GitHubOAuthService.prune_states(self)`: Implements prune states behavior.
- `GoogleOAuthService`: Runtime data object.
  - `GoogleOAuthService.enabled(self)`: Implements enabled behavior.
  - `GoogleOAuthService.authorization_url(self, redirect_uri)`: Implements authorization url behavior.
  - `GoogleOAuthService.complete(self, code, state, redirect_uri)`: Implements complete behavior.
  - `GoogleOAuthService.exchange_code(self, code, redirect_uri)`: Exchanges an OAuth authorization code for an access token.
  - `GoogleOAuthService.fetch_user(self, access_token)`: Fetches repository content, commits, user profiles, or store pages.
  - `GoogleOAuthService.consume_state(self, state)`: Implements consume state behavior.
  - `GoogleOAuthService.prune_states(self)`: Implements prune states behavior.
- `AuthManager`: Coordinator object that manages related runtime state.
  - `AuthManager.session(self, cookie_header)`: Creates, reads, or serializes session state.
  - `AuthManager.create_session(self, user)`: Creates schemas, clients, sessions, rows, or report structures.
  - `AuthManager.logout(self, session_id)`: Ends the active UI session.
  - `AuthManager.status(self, record)`: Returns current scan, store, database, or credential status.
  - `AuthManager.create_test_session(self)`: Creates schemas, clients, sessions, rows, or report structures.
  - `AuthManager.apply_credentials(self, payload, record)`: Implements apply credentials behavior.
  - `AuthManager.delete_credential(self, provider, record)`: Removes saved credentials or persisted values.

Functions:
- `auth_state_dir(reports_root)`: Builds or evaluates authentication-related data.
- `env_value(*names)`: Reads environment variables or feature flags.
- `provider_name(value)`: Reads provider-specific token, project, or client values.
- `cookie_value(cookie_header, name)`: Builds or reads session cookie values.
- `session_cookie(session_id, secure=...)`: Creates, reads, or serializes session state.
- `expired_session_cookie(secure=...)`: Builds an expired session cookie header.
- `chmod_private(path, mode)`: Helper for chmod private.
- `utc_timestamp()`: Returns a UTC timestamp string.

### `appsec_scan_router.azure`
Azure DevOps API client used by the scanner without cloning repositories.

Constants: `LOGGER`, `DEFAULT_ADO_REQUESTS_PER_SECOND`, `DEFAULT_ADO_POOL_SIZE`, `DEFAULT_ADO_MAX_RETRIES`, `DEFAULT_ADO_LOW_REMAINING_BACKOFF_SECONDS`

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
- `AzureDevOpsThrottle`: Process-local request pacer that smooths Azure DevOps API calls across worker threads.
  - `AzureDevOpsThrottle.wait(self)`: Waits until the next request slot is available.
  - `AzureDevOpsThrottle.observe(self, response)`: Applies Azure DevOps throttling hints from response headers.
  - `AzureDevOpsThrottle.defer(self, seconds)`: Defers future requests for a bounded backoff period.

Functions:
- `provider_connection_message(provider, url, exc)`: Reads provider-specific token, project, or client values.
- `positive_float_env(name, default)`: Reads a non-negative float environment override.
- `positive_int_env(name, default)`: Reads a positive integer environment override.
- `retry_after_seconds(value)`: Parses a `Retry-After` value in seconds or HTTP date form.
- `float_header(value)`: Parses numeric HTTP header values.

### `appsec_scan_router.cli`
Command-line parser and executable entry point.

Functions:
- `parse_args(argv)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `validate_args(args, application_types, ado_org_pats)`: Helper for validate args.
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

Constants: `API_VERSION`, `DEFAULT_TIMEOUT_SECONDS`, `DEFAULT_MAX_WORKERS`, `DEFAULT_BRANCH_WORKERS`, `DEFAULT_CONTENT_WORKERS`, `DEFAULT_COMMIT_PAGE_SIZE`, `DEFAULT_BRANCH_AGE_DAYS`, `DEFAULT_STORE_COUNTRY`, `DEFAULT_STORE_TIMEOUT_SECONDS`, `DEFAULT_ACTIVITY_MODE`, `DEFAULT_OUT_PREFIX`, `DEFAULT_POSTGRES_SCHEMA`, `DEFAULT_POSTGRES_TABLE`, `DEFAULT_POSTGRES_HOST`, `DEFAULT_POSTGRES_PORT`, `DEFAULT_POSTGRES_DATABASE`, `DEFAULT_POSTGRES_USER`, `DEFAULT_POSTGRES_PASSWORD`, `MISSING_REQUESTS_MESSAGE`, `MISSING_PSYCOPG_MESSAGE`, `MISSING_CRYPTOGRAPHY_MESSAGE`, `FALLBACK_BRANCH_PRIORITY`, `ACTIVE_SHEET_NAME`, `OLDER_SHEET_NAME`, `KNOWN_CATEGORIES`, `CATEGORY_FIELDNAMES`, `KNOWN_INVENTORY_TYPES`, `TYPE_FIELDNAMES`, `APPLICATION_TYPE_LABELS`, `STORE_FIELDNAMES`, `CONTENT_FILES_TO_FETCH`, `CONTENT_FILE_SUFFIXES`, `INVENTORY_FIELDNAMES`, `SONARQUBE_FIELDNAMES`

Functions:
- `active_sheet_name(branch_age_days=...)`: Helper for active sheet name.
- `older_sheet_name(branch_age_days=...)`: Helper for older sheet name.

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
- `has_script(data, names)`: Helper for has script.
- `dependency_text_has_any(content, names)`: Helper for dependency text has any.
- `dependency_text_matches(content, names)`: Helper for dependency text matches.
- `detect_ai_dependency_name_evidence(path, dependency_names, source_label)`: Classifies a repository from paths and manifest evidence.
- `detect_ai_dependency_text_evidence(path, content, source_label)`: Classifies a repository from paths and manifest evidence.
- `collect_ai_dependency_evidence(path, source_label, matcher)`: Collects evidence, targets, metadata, or related values from input data.
- `ai_capability_evidence(path, category, detail, weight)`: Helper for ai capability evidence.
- `format_matches(matches)`: Formats values for logs, reports, or API responses.
- `detect_expo_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_expo_dynamic_config_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_capacitor_json_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_capacitor_ts_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_cordova_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_csproj_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `detect_pipeline_evidence(path, content)`: Classifies a repository from paths and manifest evidence.
- `dedupe_evidence(evidence)`: Helper for dedupe evidence.

### `appsec_scan_router.entrypoint`
Container entry point that dispatches UI or CLI modes.

Functions:
- `main()`: Runs the module as a command-line entry point.
- `exec_module(module, args)`: Helper for exec module.
- `exec_callable(module, function, args)`: Helper for exec callable.

### `appsec_scan_router.github`
GitHub Enterprise API client and URL normalization utilities.

Constants: `LOGGER`, `GITHUB_DEPLOYMENT_ENVIRONMENTS`, `GITHUB_SUCCESSFUL_DEPLOYMENT_STATES`

Classes:
- `GitHubAppCredentials`: Validated GitHub App ID, installation ID, and PEM key configuration.
  - `GitHubAppCredentials.from_values(app_id, installation_id, private_key, private_key_file)`: Resolves explicit or environment-backed App settings.
  - `GitHubAppCredentials.from_env()`: Loads App settings from environment variables.
- `GitHubAppTokenProvider`: Signs App JWTs and caches installation access tokens until shortly before expiry.
  - `GitHubAppTokenProvider.token(self)`: Returns a current installation token, refreshing it when needed.
  - `GitHubAppTokenProvider.close(self)`: Releases the token request session.
- `GitHubEnterpriseClient`: Provider or external-service client that wraps network access and retries.
  - `GitHubEnterpriseClient.close(self)`: Releases open sessions, files, or listeners.
  - `GitHubEnterpriseClient.session(self)`: Creates, reads, or serializes session state.
  - `GitHubEnterpriseClient.get(self, url, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `GitHubEnterpriseClient.get_json(self, path, params=...)`: Retrieves a provider, HTTP, session, or report value.
  - `GitHubEnterpriseClient.list_projects(self)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.list_repos(self, project_name)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.repo_from_api(self, repo)`: Implements repo from api behavior.
  - `GitHubEnterpriseClient.list_branches(self, project_name, repo_id)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.list_build_definitions_for_repo(self, project_name, repo_id)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.deployment_is_successful(self, repo_id, deployment)`: Implements deployment is successful behavior.
  - `GitHubEnterpriseClient.list_repo_items(self, project_name, repo_id, branch_name=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.tree_ref_for_branch(self, repo_id, branch_name)`: Implements tree ref for branch behavior.
  - `GitHubEnterpriseClient.list_commits(self, project_name, repo_id, max_commits=..., page_size=..., branch_name=...)`: Lists provider resources such as projects, repositories, branches, or commits.
  - `GitHubEnterpriseClient.fetch_file_content(self, project_name, repo_id, file_path, branch_name=...)`: Fetches repository content, commits, user profiles, or store pages.

Functions:
- `github_commit_to_activity_commit(commit)`: Handles GitHub Enterprise provider behavior.
- `normalize_github_api_url(base_url)`: Normalizes input into the canonical representation used by the scanner.
- `normalize_github_owner(value)`: Converts a GitHub owner URL or owner name to the canonical owner value.
- `parse_github_urls(value, default)`: Parses and deduplicates multiple GitHub owner URLs or names.
- `insecure_provider_urls_allowed()`: Helper for insecure provider urls allowed.
- `allowed_github_hosts()`: Helper for allowed github hosts.
- `github_env_value(*names)`: Reads the first configured GitHub App environment value.
- `parse_github_expiry(value)`: Parses an installation token expiration timestamp.
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
- `xcode_setting_value(content, key)`: Helper for xcode setting value.
- `collect_android_strings(file_contents)`: Collects evidence, targets, metadata, or related values from input data.
- `parse_android_manifest(content, string_resources=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `resolve_android_label(label, string_resources)`: Resolves placeholders or labels to concrete values.
- `parse_capacitor_json(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_capacitor_ts(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_cordova_config(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_expo_config(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_expo_dynamic_config(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_gradle_metadata(content, properties=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `gradle_assignment_value(content, key)`: Helper for gradle assignment value.
- `parse_pubspec(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_package_json(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_csproj(content, properties=...)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_msbuild_props(content)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.

### `appsec_scan_router.models`
Dataclasses and exceptions that define scanner contracts.

Classes:
- `AzureDevOpsError`: Exception type used to preserve provider-specific error details.
- `AzureDevOpsOrgPat`: Runtime data object.
- `SourceTargetFilter`: Runtime data object.
- `ScanConfig`: Configuration object that carries validated runtime settings.
- `RepoScanTarget`: Runtime data object.
- `BranchScanTarget`: Runtime data object.
- `MobileAppMetadata`: Dataclass that carries extracted metadata between scanner stages.
- `RepoActivityMetadata`: Dataclass that carries extracted metadata between scanner stages.
- `StoreListing`: Runtime data object.
- `DetectionEvidence`: Runtime data object.
  - `DetectionEvidence.as_dict(self)`: Implements as dict behavior.

### `appsec_scan_router.org_tokens`
Parser and serializer for multi-organization Azure DevOps PAT configuration.

Functions:
- `parse_ado_org_pat_values(values)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_ado_org_pat_value(value)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `parse_ado_org_pat_sequence(values)`: Parses text, JSON, XML, YAML, dates, arguments, or provider values.
- `split_ado_org_pat_text(text)`: Splits delimited configuration text into entries.
- `make_ado_org_pat(org, pat)`: Constructs a validated dataclass or parsed object.
- `ado_org_pats_to_json(org_pats)`: Helper for ado org pats to json.

### `appsec_scan_router.observability`
Structured logging configuration and provider-authentication audit events.

Functions:
- `configure_logging(verbose, dsn, schema, source)`: Configures console logging and optional PostgreSQL persistence.
- `observability_dsn(explicit_dsn)`: Resolves the observability DSN from explicit or environment configuration.
- `log_github_app_context(app_id, installation_id, scan_id, owner_user_id, owner_user_login)`: Records non-secret GitHub App identifiers in structured logs.

### `appsec_scan_router.postgres`
PostgreSQL schema creation, normalized upserts, status checks, and exports.

Constants: `CONTROL_CHARACTER_RE`, `SQL_NAME_RE`, `NORMALIZED_TABLES`, `EXPORT_COLUMNS`, `PRIMARY_KEY_COLUMNS`, `POSTGRES_COLUMNS`, `FLAT_TABLE_MIGRATIONS`

Classes:
- `PostgresLogHandler`: Persists sanitized structured log records in `observability_events` without blocking the application when PostgreSQL is unavailable.
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
- `create_observability_table(connection, schema)`: Creates the structured service event table and indexes.
- `create_export_view(connection, schema)`: Creates schemas, clients, sessions, rows, or report structures.
- `database_status(dsn, schema=..., table=..., owner_user_id=...)`: Reads, writes, exports, or reports PostgreSQL database state.
- `export_inventory_rows(dsn, schema=..., owner_user_id=..., limit=...)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `export_inventory_csv(dsn, schema=..., owner_user_id=..., limit=...)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `export_inventory_json(dsn, schema=..., owner_user_id=..., limit=...)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `normalized_row_count(connection, schema, owner_user_id)`: Helper for normalized row count.
- `flat_row_count(connection, schema, table, owner_user_id)`: Reads or writes the flat compatibility PostgreSQL table.
- `store_listing_rows(result)`: Looks up, validates, or reports app-store data.
- `schema_table_parts(schema, table)`: Helper for schema table parts.
- `table_identifier(table, schema=...)`: Builds safe PostgreSQL table identifiers.
- `object_identifier(schema, name)`: Builds safe PostgreSQL object identifiers.
- `sql_name(value, label)`: Helper for sql name.
- `index_name_prefix(table)`: Builds safe PostgreSQL index names.
- `text_value(value)`: Normalizes values for safe text output.
- `semicolon_values(value)`: Helper for semicolon values.
- `timestamp_value(value)`: Converts values into PostgreSQL timestamp-compatible strings.
- `int_value(value)`: Converts a value into an integer where possible.
- `bool_value(value)`: Converts a value into a boolean representation.
- `json_value(value)`: Normalizes or exports JSON-compatible values.
- `postgres_json_value(value)`: Builds PostgreSQL DSNs or configuration values.
- `export_cell(value)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `postgres_error_message(error)`: Builds PostgreSQL DSNs or configuration values.

### `appsec_scan_router.reports`
Streaming XLSX inventory reports, Semgrep target lists, and SonarQube target manifests.

Constants: `WORKBOOK_COLUMN_WIDTHS`

Classes:
- `StreamingReportWriter`: Context-managed writer that streams results to reports or storage.
  - `StreamingReportWriter.__enter__(self)`: Opens the context-managed resource and returns it for use.
  - `StreamingReportWriter.__exit__(self, exc_type, exc_value, traceback)`: Closes the context-managed resource when the block exits.
  - `StreamingReportWriter.write_result(self, result)`: Writes files, database rows, server events, or response payloads.
  - `StreamingReportWriter.flush(self)`: Implements flush behavior.
  - `StreamingReportWriter.close(self)`: Releases open sessions, files, or listeners.

Functions:
- `write_outputs(results, out_dir, out_prefix, branch_age_days=..., application_types=...)`: Writes XLSX, Semgrep, and SonarQube outputs.
- `sonarqube_project_row(result)`: Builds a SonarQube target row.
- `workbook_cell_value(value)`: Formats values for Excel workbook output.
- `report_file_stem(out_prefix, application_types=...)`: Builds a report filename stem that includes selected application types.
- `application_type_label(application_types=...)`: Builds the application-type label used in report filenames.
- `safe_file_part(value)`: Normalizes a value for use in generated filenames.

### `appsec_scan_router.scanner`
Core orchestration for provider discovery, branch resolution, content fetching, detection, enrichment, and report/database output.

Constants: `LOGGER`

Functions:
- `scan_to_reports(config)`: Runs or coordinates repository and branch scanning.
- `scan(config, on_result=...)`: Runs or coordinates repository and branch scanning.
- `scan_ado_organizations(config, on_result=...)`: Runs the Azure DevOps portion of a multi-organization or mixed scan.
- `scan_github_organizations(config, on_result=...)`: Runs the GitHub portion for each configured owner URL.
- `scan_mixed(config, on_result=...)`: Runs Azure DevOps and GitHub Enterprise through one result callback.
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
- `log_detected_result(result)`: Helper for log detected result.
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
- `normalized_branch_key(value)`: Helper for normalized branch key.
- `branch_age_bucket(last_updated, branch_age_days, now=...)`: Computes branch metadata, branch selection, or branch report values.
- `identifier_status(identifier)`: Builds or validates mobile/application identifier values.
- `category_columns(categories)`: Builds category-specific report columns.
- `type_columns(inventory_types)`: Builds inventory type report columns.
- `inventory_types_from_categories(categories)`: Builds inventory names, versions, types, or report fields.
- `normalize_application_types(application_types)`: Normalizes input into the canonical representation used by the scanner.
- `inventory_type_matches(inventory_types, application_types)`: Builds inventory names, versions, types, or report fields.
- `store_lookup_allowed(application_types)`: Looks up, validates, or reports app-store data.
- `log_scan_progress(repositories_prepared, repositories_total, branches_scanned, branches_total)`: Helper for log scan progress.
- `repo_source_url(repo)`: Helper for repo source url.
- `scanner_target_ref(source_url, branch_name)`: Builds scanner target references or rows.
- `sonar_project_key(project_name, repo_name, branch_name)`: Builds SonarQube project identifiers or rows.
- `inventory_name_from_metadata(metadata, contents, repo_name)`: Builds inventory names, versions, types, or report fields.
- `inventory_version_from_metadata(metadata, contents)`: Builds inventory names, versions, types, or report fields.
- `primary_language_for_branch(contents, paths, categories)`: Determines the primary language or key report value.
- `package_json_language(contents)`: Helper for package json language.
- `merged_package_dependency_names(contents)`: Merges dependency maps into a single dependency set.
- `first_manifest_value(*values)`: Returns the first usable value from a sequence.
- `package_json_value(contents, key)`: Helper for package json value.
- `pyproject_value(contents, key)`: Helper for pyproject value.
- `pom_xml_value(contents, tag_name)`: Helper for pom xml value.
- `csproj_value(contents, tag_name)`: Helper for csproj value.
- `pubspec_value(contents, key)`: Helper for pubspec value.
- `fetch_repo_activity(client, project_name, repo_id, branch_name, max_commits, activity_mode)`: Fetches repository content, commits, user profiles, or store pages.
- `fetch_contents(client, project_name, repo_id, branch_name, paths, executor)`: Fetches repository content, commits, user profiles, or store pages.
- `collect_targets(client, project_name, target_filters=...)`: Collects evidence, targets, metadata, or related values from input data.
- `source_organization(client)`: Builds provider target filters or target labels.
- `selected_project_names(organization, project_name, target_filters=...)`: Helper for selected project names.
- `target_filters_for_source(target_filters, organization)`: Builds or filters provider scan targets.
- `target_filter_matches_source(filter_org, organization)`: Builds or filters provider scan targets.
- `dedupe_values(values)`: Helper for dedupe values.
- `iter_completed_branch_target_lists(repo_executor, client, targets, max_in_flight)`: Yields completed asynchronous work items.
### `appsec_scan_router.sdk`
Small callable SDK wrapper around scanner configuration and execution.

Classes:
- `ApplicationInventoryService`: Runtime data object.
  - `ApplicationInventoryService.scan(self, on_result=...)`: Runs or coordinates repository and branch scanning.
  - `ApplicationInventoryService.scan_to_reports(self)`: Runs or coordinates repository and branch scanning.

### `appsec_scan_router.store_lookup`
Apple App Store and Google Play lookup and validation helpers.

Constants: `LOGGER`, `APPLE_PLATFORM`, `GOOGLE_PLATFORM`, `APPLE_DISPLAY_NAME`, `GOOGLE_DISPLAY_NAME`, `CROSS_PLATFORM_CATEGORIES`, `BOTH_STORE_PLATFORMS`, `STORE_IDENTIFIER_PATTERN`

Classes:
- `StoreLookupClient`: Provider or external-service client that wraps network access and retries across one or more country stores.
  - `StoreLookupClient.session(self)`: Creates, reads, or serializes session state.
  - `StoreLookupClient.close(self)`: Releases open sessions, files, or listeners.
  - `StoreLookupClient.lookup(self, identifier, categories)`: Implements lookup behavior.
- `StoreLookupClient.lookup_platform(self, platform, identifier, country=...)`: Implements lookup platform behavior for a selected country.
  - `StoreLookupClient.lookup_apple_app_store(self, identifier)`: Implements lookup apple app store behavior.
  - `StoreLookupClient.lookup_google_play(self, identifier)`: Implements lookup google play behavior.
- `MetaTagParser`: Runtime data object.
  - `MetaTagParser.handle_starttag(self, tag, attrs)`: Handles a UI HTTP route or asynchronous scan result.
  - `MetaTagParser.handle_endtag(self, tag)`: Handles a UI HTTP route or asynchronous scan result.
  - `MetaTagParser.handle_data(self, data)`: Handles a UI HTTP route or asynchronous scan result.

Functions:
- `target_store_platforms(categories)`: Builds or filters provider scan targets.
- `store_columns(identifier, categories, store_client)`: Looks up, validates, or reports app-store data.
- `disabled_store_listings()`: Builds disabled or unavailable store lookup values.
- `identifier_missing_store_listings(categories)`: Builds or validates mobile/application identifier values.
- `invalid_identifier_store_listings(categories, identifier)`: Helper for invalid identifier store listings.
- `is_store_identifier_candidate(identifier)`: Evaluates a predicate used by detection, validation, or UI flow.
- `store_columns_from_listings(listings)`: Looks up, validates, or reports app-store data.
- `aggregate_platform_listings(platform, listings)`: Combines country-specific listings for the existing report columns.
- `listing_column_values(platform, listing)`: Helper for listing column values.
- `store_validation_result(listings)`: Looks up, validates, or reports app-store data.
- `listing_validation_result(listing)`: Helper for listing validation result.
- `boolean_text(value)`: Converts a value into a boolean representation.
- `aggregate_store_status(listings)`: Aggregates lower-level values into a report-ready status.
- `display_name_for_platform(platform)`: Formats a user-facing label.
- `normalize_google_play_title(title)`: Normalizes input into the canonical representation used by the scanner.
- `google_play_not_found_text(text)`: Handles Google or Google Play provider behavior.
- `google_play_app_page(meta, title, identifier)`: Handles Google or Google Play provider behavior.
- `extract_google_play_version(text)`: Extracts structured metadata from manifests, commits, or report rows.
- `extract_google_play_updated(text)`: Extracts structured metadata from manifests, commits, or report rows.
- `regex_store_value(text, pattern)`: Helper for regex store value.
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
- `ScanRun`: Runtime data object.
  - `ScanRun.append_log(self, line)`: Implements append log behavior.
  - `ScanRun.set_status(self, status, exit_code=...)`: Implements set status behavior.
  - `ScanRun.publish(self, event, data)`: Implements publish behavior.
  - `ScanRun.add_listener(self)`: Adds an item to the current in-memory collection or UI state.
  - `ScanRun.remove_listener(self, listener)`: Removes an item from UI state or listener collections.
  - `ScanRun.close_listeners(self)`: Releases open sessions, files, or listeners.
  - `ScanRun.report_files(self)`: Builds report metadata or content types.
  - `ScanRun.summary(self)`: Implements summary behavior.
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
  - `ApplicationInventoryServiceHandler.handle_health(self)`: Returns database-backed service health and observability status.
  - `ApplicationInventoryServiceHandler.handle_metrics(self)`: Returns scan counters and observability configuration.
  - `ApplicationInventoryServiceHandler.handle_source_targets(self)`: Handles a UI HTTP route or asynchronous scan result.
  - `ApplicationInventoryServiceHandler.send_static(self, name, content_type)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.send_report(self, run, filename)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.stream_scan_events(self, run)`: Streams server-sent scan events to the browser.
  - `ApplicationInventoryServiceHandler.write_event(self, event, data)`: Writes files, database rows, server events, or response payloads.
  - `ApplicationInventoryServiceHandler.read_json(self)`: Reads request bodies or encrypted credential state.
  - `ApplicationInventoryServiceHandler.send_json(self, payload, status=..., headers=...)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.send_bytes(self, content, content_type, status=..., headers=...)`: Sends an HTTP response body from the UI server.
  - `ApplicationInventoryServiceHandler.log_message(self, format, *args)`: Implements log message behavior.
  - `ApplicationInventoryServiceHandler.redirect(self, location, cookie=...)`: Implements redirect behavior.
  - `ApplicationInventoryServiceHandler.end_headers(self)`: Implements end headers behavior.
  - `ApplicationInventoryServiceHandler.current_session(self)`: Returns the current request/session state.
  - `ApplicationInventoryServiceHandler.require_session(self)`: Requires a valid authenticated session before continuing.
  - `ApplicationInventoryServiceHandler.valid_csrf(self, record)`: Validates session or request state.
  - `ApplicationInventoryServiceHandler.redirect_uri(self, provider)`: Implements redirect uri behavior.

Functions:
- `normalize_scan_config(config)`: Normalizes input into the canonical representation used by the scanner.
- `normalize_database_config(config)`: Normalizes input into the canonical representation used by the scanner.
- `discover_source_targets(config)`: Discovers source targets from provider APIs.
- `discover_azure_targets(config, timeout)`: Discovers source targets from provider APIs.
- `discover_github_targets(config, timeout)`: Discovers source targets from provider APIs.
- `discovery_token(config, provider)`: Helper for discovery token.
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
- `run_owner_id(run)`: Helper for run owner id.
- `ado_org_summary(org_pats)`: Helper for ado org summary.
- `clean_choice(value, allowed, default)`: Normalizes text by trimming, removing placeholders, or rejecting unresolved values.
- `safe_prefix(value)`: Validates and sanitizes URLs, headers, prefixes, or file names.
- `normalize_ui_application_types(value)`: Normalizes input into the canonical representation used by the scanner.
- `postgres_dsn_from_config(config)`: Builds PostgreSQL DSNs or configuration values.
- `positive_int(value, default)`: Parses a positive integer with a default fallback.
- `nonnegative_int(value, default)`: Parses a non-negative integer with a default fallback.
- `utc_now()`: Returns a UTC timestamp string.
- `secure_cookie()`: Helper for secure cookie.
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
- `xml_text(content, tag_name)`: Helper for xml text.
- `regex_value(content, pattern)`: Helper for regex value.
- `confidence_rank(confidence)`: Helper for confidence rank.

## Browser UI Functions

### `appsec_scan_router/ui_static/app.js`
Browser-side controller for login, scan setup, progress monitoring, reports, database actions, and UI state.

Functions:
- `addAdoOrgPat()`: Adds an item to the current in-memory collection or UI state.
- `addSelectedTarget(target)`: Adds an item to the current in-memory collection or UI state.
- `applicationTypeLabel(type)`: Helper for application type label.
- `applicationTypesLabel(applicationTypes)`: Helper for application types label.
- `applyDefaultValues()`: Helper for apply default values.
- `authHeaders(jsonBody)`: Builds or evaluates authentication-related data.
- `authProviderName(provider)`: Builds or evaluates authentication-related data.
- `authProviders(session)`: Builds or evaluates authentication-related data.
- `bindEvents()`: Helper for bind events.
- `capitalize(text)`: Helper for capitalize.
- `checkDatabase()`: Checks current UI or provider state.
- `checkedValues(name)`: Helper for checked values.
- `clearDiscoveredTargets({silent = false} = {})`: Clears current UI state or selected values.
- `clearSelectedTargets()`: Clears current UI state or selected values.
- `closeEventSource()`: Releases open sessions, files, or listeners.
- `commitPendingAdoOrgPat({silent = false} = {})`: Helper for commit pending ado org pat.
- `copyCommand()`: Copies generated command text for the UI user.
- `databasePayload()`: Reads, writes, exports, or reports PostgreSQL database state.
- `downloadBlob(blob, filename)`: Downloads a client-side blob or log payload.
- `downloadLogs()`: Downloads a client-side blob or log payload.
- `durationText(totalSeconds)`: Helper for duration text.
- `escapeHtml(value)`: Helper for escape html.
- `exportDatabase(format)`: Exports normalized inventory data to CSV, JSON, or cell text.
- `forgetSavedToken()`: Removes a saved provider token from UI state and encrypted storage.
- `formatBytes(value)`: Formats values for logs, reports, or API responses.
- `formatDate(value)`: Formats values for logs, reports, or API responses.
- `formPayload()`: Helper for form payload.
- `handleAdoOrgPatKeydown(event)`: Handles a UI HTTP route or asynchronous scan result.
- `handleSsoClick(event)`: Handles a UI HTTP route or asynchronous scan result.
- `isLoggedIn()`: Evaluates a predicate used by detection, validation, or UI flow.
- `listenToScan(scanId)`: Helper for listen to scan.
- `loadForm()`: Loads state or source data from disk, HTTP, or form input.
- `loadScans(preferredId = "")`: Loads state or source data from disk, HTTP, or form input.
- `loadSession()`: Loads state or source data from disk, HTTP, or form input.
- `loadSourceTargets()`: Loads state or source data from disk, HTTP, or form input.
- `logout()`: Ends the active UI session.
- `maskSecret(value)`: Masks a secret for display.
- `mergeScan(scan)`: Helper for merge scan.
- `normalizedTarget(target)`: Helper for normalized target.
- `notify(message)`: Helper for notify.
- `numberValue(data, name, fallback)`: Helper for number value.
- `pluralize(noun, count)`: Helper for pluralize.
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
- `resetDefaults()`: Helper for reset defaults.
- `saveForm()`: Helper for save form.
- `scanEta(scan)`: Runs or coordinates repository and branch scanning.
- `scanPercent(scan)`: Runs or coordinates repository and branch scanning.
- `scanProgress(scan)`: Runs or coordinates repository and branch scanning.
- `scanProgressDetail(scan)`: Runs or coordinates repository and branch scanning.
- `scanRuntime(scan)`: Runs or coordinates repository and branch scanning.
- `selectScan(scan, connect = true)`: Selects branch or UI target values from candidates.
- `selectVisibleTargets()`: Selects branch or UI target values from candidates.
- `setActiveView(viewId)`: Helper for set active view.
- `setBusy(isBusy)`: Helper for set busy.
- `setCheckboxGroup(name, values)`: Helper for set checkbox group.
- `setDatabaseBusy(isBusy)`: Helper for set database busy.
- `setTargetBusy(isBusy)`: Helper for set target busy.
- `showAuthResult()`: Helper for show auth result.
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
- `tick()`: Helper for tick.
- `toggleToken()`: Toggles UI state such as token visibility.
- `value(data, name)`: Helper for value.
- `visibleTargets()`: Returns currently visible UI targets.
