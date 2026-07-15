from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import os
import re
import threading
import time
import weakref
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

from .constants import (
    DEFAULT_GITHUB_API_URL,
    DEFAULT_COMMIT_PAGE_SIZE,
    DEFAULT_GITHUB_APP_ID,
    DEFAULT_GITHUB_APP_INSTALLATION_ID,
    MISSING_REQUESTS_MESSAGE,
)
from .models import AzureDevOpsError
from .azure import float_header, positive_float_env, positive_int_env, provider_connection_message, retry_after_seconds
from .utils import clean_value

try:
    import jwt
except ImportError:
    jwt = None

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None


LOGGER = logging.getLogger("appsec_scan_router")
GITHUB_DEPLOYMENT_ENVIRONMENTS = ("production", "prod", "preprod", "pre-prod")
GITHUB_SUCCESSFUL_DEPLOYMENT_STATES = frozenset({"success"})
DEFAULT_GITHUB_REQUESTS_PER_SECOND = 8.0
DEFAULT_GITHUB_POOL_SIZE = 8
DEFAULT_GITHUB_MAX_RETRIES = 5
DEFAULT_GITHUB_RATE_LIMIT_RESERVE = 50


@dataclass
class GitHubAppTokenState:
    token: str = ""
    expires_at: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)


_TOKEN_STATES: weakref.WeakValueDictionary[str, GitHubAppTokenState] = weakref.WeakValueDictionary()
_TOKEN_STATES_LOCK = threading.Lock()
_THROTTLES: weakref.WeakValueDictionary[str, GitHubThrottle] = weakref.WeakValueDictionary()
_THROTTLES_LOCK = threading.Lock()


@dataclass(frozen=True)
class GitHubAppCredentials:
    app_id: str
    installation_id: str
    private_key: str

    @classmethod
    def from_values(
        cls,
        app_id: str = "",
        installation_id: str = "",
        private_key: str = "",
        private_key_file: str = "",
    ) -> GitHubAppCredentials | None:
        configured_app_id = clean_value(app_id) or github_env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_ID", "APPSEC_INVENTORY_GITHUB_APP_ID", "GITHUB_APP_ID", "GHE_APP_ID"
        )
        configured_installation_id = clean_value(installation_id) or github_env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID",
            "APPSEC_INVENTORY_GITHUB_APP_INSTALLATION_ID",
            "GITHUB_APP_INSTALLATION_ID",
            "GHE_APP_INSTALLATION_ID",
        )
        resolved_private_key = clean_value(private_key) or github_env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY",
            "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY",
            "GITHUB_APP_PRIVATE_KEY",
            "GHE_APP_PRIVATE_KEY",
        )
        resolved_private_key_file = clean_value(private_key_file) or github_env_value(
            "APPLICATION_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
            "APPSEC_INVENTORY_GITHUB_APP_PRIVATE_KEY_FILE",
            "GITHUB_APP_PRIVATE_KEY_FILE",
            "GHE_APP_PRIVATE_KEY_FILE",
        )
        if not any((configured_app_id, configured_installation_id, resolved_private_key, resolved_private_key_file)):
            return None
        resolved_app_id = configured_app_id or DEFAULT_GITHUB_APP_ID
        resolved_installation_id = configured_installation_id or DEFAULT_GITHUB_APP_INSTALLATION_ID
        if not resolved_private_key and not resolved_private_key_file:
            if resolved_app_id == DEFAULT_GITHUB_APP_ID and resolved_installation_id == DEFAULT_GITHUB_APP_INSTALLATION_ID:
                return None
            raise ValueError("GitHub App private key or private key file is required.")
        if not resolved_app_id or not resolved_app_id.isdigit():
            raise ValueError("GitHub App ID must be numeric.")
        if not resolved_installation_id or not resolved_installation_id.isdigit():
            raise ValueError("GitHub App installation ID must be numeric.")
        if not resolved_private_key and resolved_private_key_file:
            try:
                resolved_private_key = Path(resolved_private_key_file).expanduser().read_text(encoding="utf-8")
            except OSError as exc:
                raise ValueError("GitHub App private key file could not be read.") from exc
        resolved_private_key = resolved_private_key.replace("\\n", "\n").strip()
        if "BEGIN" not in resolved_private_key or "PRIVATE KEY" not in resolved_private_key:
            raise ValueError("GitHub App private key must be a PEM private key.")
        return cls(resolved_app_id, resolved_installation_id, resolved_private_key)

    @classmethod
    def from_env(cls) -> GitHubAppCredentials | None:
        return cls.from_values()


class GitHubAppTokenProvider:
    def __init__(self, base_url: str, credentials: GitHubAppCredentials, timeout_seconds: int) -> None:
        if requests is None or HTTPAdapter is None or Retry is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)
        if jwt is None:
            raise SystemExit("GitHub App authentication requires PyJWT.")
        self.base_url = base_url
        self.credentials = credentials
        self.timeout_seconds = timeout_seconds
        self._state = shared_token_state(base_url, credentials)
        self._session = requests.Session()
        retry = Retry(
            total=3,
            connect=2,
            read=2,
            other=0,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"POST"}),
            respect_retry_after_header=True,
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retry))
        self._session.mount("http://", HTTPAdapter(max_retries=retry))
        LOGGER.info(
            "GitHub App configured app_id=%s installation_id=%s",
            credentials.app_id,
            credentials.installation_id,
            extra={
                "event_type": "github_app.configured",
                "metadata": {
                    "app_id": credentials.app_id,
                    "installation_id": credentials.installation_id,
                },
            },
        )

    def close(self) -> None:
        self._session.close()

    def token(self) -> str:
        with self._state.lock:
            if self._state.token and self._state.expires_at > time.time() + 60:
                return self._state.token
            return self._refresh()

    def _refresh(self) -> str:
        assertion = self._app_jwt()
        url = f"{self.base_url}/app/installations/{self.credentials.installation_id}/access_tokens"
        headers = {
            "Authorization": f"Bearer {assertion}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "application-inventory-service/1.6.13",
        }
        try:
            response = self._session.post(url, headers=headers, timeout=self.timeout_seconds)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise AzureDevOpsError(provider_connection_message("GitHub Enterprise App", url, exc)) from exc
        except ValueError as exc:
            raise AzureDevOpsError(f"GitHub Enterprise App returned invalid JSON from {url}") from exc
        token = clean_value(data.get("token")) if isinstance(data, dict) else ""
        if not token:
            raise AzureDevOpsError("GitHub Enterprise App did not return an installation access token.")
        expires_at = parse_github_expiry(data.get("expires_at")) if isinstance(data, dict) else 0.0
        self._state.token = token
        self._state.expires_at = expires_at or time.time() + 3600
        return token

    def _app_jwt(self) -> str:
        now = int(time.time())
        try:
            encoded = jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": self.credentials.app_id},
                self.credentials.private_key,
                algorithm="RS256",
            )
        except Exception as exc:
            raise AzureDevOpsError("GitHub App private key could not sign the application JWT.") from exc
        return encoded.decode("ascii") if isinstance(encoded, bytes) else encoded


def shared_token_state(base_url: str, credentials: GitHubAppCredentials) -> GitHubAppTokenState:
    key_fingerprint = hashlib.sha256(credentials.private_key.encode()).hexdigest()[:16]
    key = f"{base_url}:{credentials.app_id}:{credentials.installation_id}:{key_fingerprint}"
    with _TOKEN_STATES_LOCK:
        state = _TOKEN_STATES.get(key)
        if state is None:
            state = GitHubAppTokenState()
            _TOKEN_STATES[key] = state
        return state


class GitHubThrottle:
    def __init__(self, requests_per_second: float, rate_limit_reserve: int) -> None:
        self.min_interval_seconds = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second
        self.rate_limit_reserve = max(0, rate_limit_reserve)
        self.lock = threading.Lock()
        self.next_request_at = 0.0
        self.block_until = 0.0

    def wait(self) -> None:
        sleep_seconds = 0.0
        with self.lock:
            now = time.monotonic()
            scheduled_at = max(self.next_request_at, self.block_until)
            if scheduled_at > now:
                sleep_seconds = scheduled_at - now
            self.next_request_at = max(scheduled_at, now) + self.min_interval_seconds
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

    def observe(self, response: requests.Response) -> None:
        retry_after = retry_after_seconds(response.headers.get("Retry-After"))
        if retry_after > 0:
            self.defer(retry_after)
            LOGGER.info("GitHub requested %.2fs client backoff.", retry_after)
            return

        remaining = float_header(response.headers.get("X-RateLimit-Remaining"))
        reset_at = float_header(response.headers.get("X-RateLimit-Reset"))
        if remaining is not None and remaining <= self.rate_limit_reserve and reset_at:
            self.defer(max(0.0, reset_at - time.time() + 1.0))
            return
        if response.status_code == 429:
            self.defer(60.0)

    def defer(self, seconds: float) -> None:
        if seconds <= 0:
            return
        with self.lock:
            self.block_until = max(self.block_until, time.monotonic() + seconds)


def shared_github_throttle(scope: str, requests_per_second: float, rate_limit_reserve: int) -> GitHubThrottle:
    with _THROTTLES_LOCK:
        throttle = _THROTTLES.get(scope)
        if throttle is None:
            throttle = GitHubThrottle(requests_per_second, rate_limit_reserve)
            _THROTTLES[scope] = throttle
        return throttle


class GitHubEnterpriseClient:
    def __init__(
        self,
        base_url: str,
        owner: str,
        token: str,
        timeout_seconds: int,
        app_credentials: GitHubAppCredentials | None = None,
    ) -> None:
        if requests is None or HTTPAdapter is None or Retry is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)

        self.base_url = normalize_github_api_url(base_url)
        self.owner = owner
        self.timeout_seconds = timeout_seconds
        self.app_credentials = app_credentials or GitHubAppCredentials.from_env()
        self._app_token_provider = (
            GitHubAppTokenProvider(self.base_url, self.app_credentials, timeout_seconds)
            if self.app_credentials
            else None
        )
        self._token = clean_value(token)
        if not self._token and not self._app_token_provider:
            raise ValueError("GitHub Enterprise requires a GitHub App configuration or access token.")
        self._headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "application-inventory-service/1.6.13",
        }
        self._retry = Retry(
            total=positive_int_env("APPLICATION_INVENTORY_GITHUB_MAX_RETRIES", DEFAULT_GITHUB_MAX_RETRIES),
            connect=0,
            read=3,
            other=0,
            backoff_factor=0.6,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        self._thread_local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()
        throttle_scope = (
            f"app:{self.app_credentials.installation_id}"
            if self.app_credentials
            else f"token:{hashlib.sha256(self._token.encode()).hexdigest()[:16]}"
        )
        self._throttle = shared_github_throttle(
            f"{self.base_url}:{throttle_scope}",
            positive_float_env(
                "APPLICATION_INVENTORY_GITHUB_REQUESTS_PER_SECOND",
                DEFAULT_GITHUB_REQUESTS_PER_SECOND,
            ),
            positive_int_env(
                "APPLICATION_INVENTORY_GITHUB_RATE_LIMIT_RESERVE",
                DEFAULT_GITHUB_RATE_LIMIT_RESERVE,
            ),
        )

    def close(self) -> None:
        if self._app_token_provider:
            self._app_token_provider.close()
        with self._sessions_lock:
            for session in self._sessions:
                session.close()
            self._sessions.clear()

    @property
    def session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(self._headers)
            pool_size = positive_int_env("APPLICATION_INVENTORY_GITHUB_POOL_SIZE", DEFAULT_GITHUB_POOL_SIZE)
            adapter = HTTPAdapter(
                max_retries=self._retry,
                pool_connections=pool_size,
                pool_maxsize=pool_size,
                pool_block=True,
            )
            session.mount("https://", adapter)
            self._thread_local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, url: str, params: dict[str, Any] | None = None) -> Any:
        try:
            self._throttle.wait()
            response = self.session.get(
                url,
                params=params,
                headers=self._authorization_headers(),
                timeout=self.timeout_seconds,
            )
            self._throttle.observe(response)
            return response
        except requests.RequestException as exc:
            raise AzureDevOpsError(provider_connection_message("GitHub Enterprise", url, exc)) from exc

    def _authorization_headers(self) -> dict[str, str]:
        if self._app_token_provider:
            return {"Authorization": f"Bearer {self._app_token_provider.token()}"}
        return {"Authorization": f"Bearer {self._token}"}

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self.get(self._url(path), params)
        self._raise_for_status(response)
        try:
            return response.json()
        except ValueError as exc:
            raise AzureDevOpsError(f"Expected JSON from {response.url}") from exc

    @staticmethod
    def _raise_for_status(response: requests.Response) -> None:
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            message = response.text[:500].replace("\n", " ")
            raise AzureDevOpsError(
                f"HTTP {response.status_code} from {response.url}: {message}",
                status_code=response.status_code,
            ) from exc

    def _get_paginated(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        max_items: int = 0,
    ) -> list[Any]:
        results: list[Any] = []
        next_url = self._url(path)
        request_params = dict(params or {})

        while next_url:
            response = self.get(next_url, request_params)
            self._raise_for_status(response)
            data = response.json()
            if isinstance(data, list):
                results.extend(data)
            elif isinstance(data, dict) and isinstance(data.get("items"), list):
                results.extend(data["items"])
            else:
                break
            if max_items and len(results) >= max_items:
                return results[:max_items]
            next_url = response.links.get("next", {}).get("url", "")
            request_params = {}

        return results

    def list_projects(self) -> list[dict[str, Any]]:
        return [{"name": self.owner}]

    def list_repos(self, project_name: str) -> list[dict[str, Any]]:
        if project_name and project_name != self.owner:
            return [self.repo_from_api(self.get_json(f"/repos/{self.owner}/{quote(project_name)}"))]

        try:
            repos = self._get_paginated(
                f"/orgs/{quote(self.owner)}/repos",
                {"type": "all", "per_page": 100},
            )
        except AzureDevOpsError as exc:
            if exc.status_code != 404:
                raise
            repos = self._get_paginated(
                f"/users/{quote(self.owner)}/repos",
                {"type": "all", "per_page": 100},
            )
        return [self.repo_from_api(repo) for repo in repos if isinstance(repo, dict)]

    def repo_from_api(self, repo: dict[str, Any]) -> dict[str, Any]:
        full_name = clean_value(repo.get("full_name"))
        name = clean_value(repo.get("name"))
        default_branch = clean_value(repo.get("default_branch"))
        homepage_url = clean_value(repo.get("homepage"))
        pages_url = github_pages_url(full_name) if repo.get("has_pages") else ""
        return {
            "id": full_name or name,
            "name": name,
            "fullName": full_name,
            "defaultBranch": f"refs/heads/{default_branch}" if default_branch else "",
            "webUrl": clean_value(repo.get("html_url")),
            "remoteUrl": clean_value(repo.get("clone_url")) or clean_value(repo.get("ssh_url")),
            "homepageUrl": homepage_url,
            "pagesUrl": pages_url,
            "isDisabled": bool(repo.get("disabled") or repo.get("archived")),
        }

    def list_branches(self, project_name: str, repo_id: str) -> list[dict[str, Any]]:
        branches = self._get_paginated(f"/repos/{quote(repo_id, safe='/')}/branches", {"per_page": 100})
        return [
            {"name": f"refs/heads/{clean_value(branch.get('name'))}"}
            for branch in branches
            if isinstance(branch, dict) and clean_value(branch.get("name"))
        ]

    def list_build_definitions_for_repo(self, project_name: str, repo_id: str) -> list[dict[str, Any]]:
        definitions: list[dict[str, Any]] = []
        for environment in GITHUB_DEPLOYMENT_ENVIRONMENTS:
            try:
                deployments = self._get_paginated(
                    f"/repos/{quote(repo_id, safe='/')}/deployments",
                    {"environment": environment, "per_page": 100},
                )
            except AzureDevOpsError as exc:
                if exc.status_code in {403, 404}:
                    continue
                raise
            for deployment in deployments:
                if not isinstance(deployment, dict):
                    continue
                ref = clean_value(deployment.get("ref"))
                if ref and self.deployment_is_successful(repo_id, deployment):
                    definitions.append({"repository": {"defaultBranch": ref}})
        return definitions

    def deployment_is_successful(self, repo_id: str, deployment: dict[str, Any]) -> bool:
        deployment_id = clean_value(deployment.get("id"))
        if not deployment_id:
            return True
        try:
            statuses = self._get_paginated(
                f"/repos/{quote(repo_id, safe='/')}/deployments/{deployment_id}/statuses",
                {"per_page": 1},
            )
        except AzureDevOpsError as exc:
            if exc.status_code in {403, 404}:
                return True
            raise
        if not statuses:
            return True
        latest = statuses[0] if isinstance(statuses[0], dict) else {}
        return clean_value(latest.get("state")).lower() in GITHUB_SUCCESSFUL_DEPLOYMENT_STATES

    def list_web_endpoints(
        self,
        project_name: str,
        repo_id: str,
        branch_name: str,
    ) -> list[dict[str, str]]:
        params: dict[str, Any] = {"per_page": 30}
        if branch_name:
            params["ref"] = branch_name
        try:
            deployments = self._get_paginated(
                f"/repos/{quote(repo_id, safe='/')}/deployments",
                params,
                max_items=30,
            )
        except AzureDevOpsError as exc:
            if exc.status_code in {403, 404}:
                return []
            raise
        deployments = sorted(deployments, key=github_deployment_environment_rank, reverse=True)
        max_environments = min(20, positive_int_env("APPLICATION_INVENTORY_GITHUB_DOMAIN_ENVIRONMENTS", 4))
        max_status_checks = max_environments * 2
        environment_checks: dict[str, int] = {}
        resolved_environments: set[str] = set()
        seen_urls: set[str] = set()
        endpoints: list[dict[str, str]] = []
        status_checks = 0
        for deployment in deployments:
            if status_checks >= max_status_checks:
                break
            if not isinstance(deployment, dict):
                continue
            environment = clean_value(deployment.get("environment")) or "default"
            environment_key = environment.casefold()
            if environment_key in resolved_environments:
                continue
            if environment_key not in environment_checks and len(environment_checks) >= max_environments:
                continue
            checks = environment_checks.get(environment_key, 0)
            if checks >= 2:
                continue
            environment_checks[environment_key] = checks + 1
            deployment_id = clean_value(deployment.get("id"))
            if not deployment_id:
                continue
            status_checks += 1
            try:
                statuses = self._get_paginated(
                    f"/repos/{quote(repo_id, safe='/')}/deployments/{deployment_id}/statuses",
                    {"per_page": 10},
                    max_items=10,
                )
            except AzureDevOpsError as exc:
                if exc.status_code in {403, 404, 422}:
                    continue
                raise
            successful_status = next(
                (
                    status
                    for status in statuses
                    if isinstance(status, dict)
                    and clean_value(status.get("state")).lower() in GITHUB_SUCCESSFUL_DEPLOYMENT_STATES
                    and clean_value(status.get("environment_url"))
                ),
                None,
            )
            if successful_status is None:
                continue
            environment_url = clean_value(successful_status.get("environment_url"))
            if environment_url in seen_urls:
                resolved_environments.add(environment_key)
                continue
            seen_urls.add(environment_url)
            resolved_environments.add(environment_key)
            endpoints.append(
                {
                    "url": environment_url,
                    "source": "github:deployment_status",
                    "confidence": "confirmed",
                    "environment": environment,
                }
            )
        return endpoints

    def list_repo_items(self, project_name: str, repo_id: str, branch_name: str | None = None) -> list[dict[str, Any]]:
        ref = quote(branch_name or "HEAD", safe="")
        data = self.get_json(f"/repos/{quote(repo_id, safe='/')}/git/trees/{ref}", {"recursive": "1"})
        if isinstance(data, dict) and data.get("truncated"):
            LOGGER.warning("GitHub returned a truncated repository tree for %s@%s", repo_id, branch_name or "HEAD")
        tree = data.get("tree") if isinstance(data, dict) else []
        return [
            {"path": f"/{item.get('path', '').lstrip('/')}"}
            for item in tree
            if isinstance(item, dict) and item.get("path")
        ]

    def list_commits(
        self,
        project_name: str,
        repo_id: str,
        max_commits: int = 0,
        page_size: int = DEFAULT_COMMIT_PAGE_SIZE,
        branch_name: str | None = None,
    ) -> list[dict[str, Any]]:
        return list(self.iter_commits(project_name, repo_id, max_commits, page_size, branch_name))

    def iter_commits(
        self,
        project_name: str,
        repo_id: str,
        max_commits: int = 0,
        page_size: int = DEFAULT_COMMIT_PAGE_SIZE,
        branch_name: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        per_page = max(1, min(page_size, 100))
        params: dict[str, Any] = {"per_page": per_page}
        if branch_name:
            params["sha"] = branch_name

        yielded = 0
        next_url = self._url(f"/repos/{quote(repo_id, safe='/')}/commits")
        request_params = params

        while next_url:
            response = self.get(next_url, request_params)
            self._raise_for_status(response)
            batch = response.json()
            if not isinstance(batch, list) or not batch:
                break

            for item in batch:
                if not isinstance(item, dict):
                    continue
                yield github_commit_to_activity_commit(item)
                yielded += 1
                if max_commits and yielded >= max_commits:
                    return
            next_url = response.links.get("next", {}).get("url", "")
            request_params = {}

        return

    def fetch_file_content(
        self,
        project_name: str,
        repo_id: str,
        file_path: str,
        branch_name: str | None = None,
    ) -> str:
        clean_path = quote(file_path.lstrip("/"), safe="/")
        params: dict[str, Any] = {}
        if branch_name:
            params["ref"] = branch_name
        try:
            data = self.get_json(f"/repos/{quote(repo_id, safe='/')}/contents/{clean_path}", params)
        except (AzureDevOpsError, requests.RequestException) as exc:
            LOGGER.debug("Failed to fetch %s in repo %s: %s", file_path, repo_id, exc)
            return ""

        if not isinstance(data, dict):
            return ""
        content = clean_value(data.get("content"))
        encoding = clean_value(data.get("encoding")).lower()
        if encoding != "base64" or not content:
            return ""
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except ValueError:
            return ""


def github_commit_to_activity_commit(commit: dict[str, Any]) -> dict[str, Any]:
    details = commit.get("commit") if isinstance(commit.get("commit"), dict) else {}
    author = details.get("author") if isinstance(details.get("author"), dict) else {}
    committer = details.get("committer") if isinstance(details.get("committer"), dict) else {}
    return {
        "author": {
            "name": clean_value(author.get("name")),
            "email": clean_value(author.get("email")),
        },
        "committer": {
            "name": clean_value(committer.get("name")),
            "email": clean_value(committer.get("email")),
            "date": clean_value(committer.get("date") or author.get("date")),
        },
    }


def github_pages_url(full_name: str) -> str:
    parts = [part for part in clean_value(full_name).split("/") if part]
    if len(parts) != 2:
        return ""
    owner, repository = parts
    host = f"{owner.lower()}.github.io"
    if repository.casefold() == host.casefold():
        return f"https://{host}"
    return f"https://{host}/{quote(repository)}"


def github_deployment_environment_rank(deployment: Any) -> int:
    if not isinstance(deployment, dict):
        return 0
    environment = re.sub(r"[^a-z0-9]+", "", clean_value(deployment.get("environment")).lower())
    if environment in {"production", "prod"}:
        return 3
    if environment in {"preproduction", "preprod", "staging", "stage"}:
        return 2
    return 1


def normalize_github_api_url(base_url: str) -> str:
    text = clean_value(base_url).rstrip("/")
    if not text:
        return DEFAULT_GITHUB_API_URL
    if "://" not in text:
        text = f"https://{text}"
    parsed = urlparse(text)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ValueError("GitHub Enterprise API URL must be an HTTP or HTTPS URL.")
    if parsed.scheme == "http" and not insecure_provider_urls_allowed():
        raise ValueError("GitHub Enterprise API URL must use HTTPS unless insecure provider URLs are explicitly allowed.")
    if parsed.username or parsed.password:
        raise ValueError("GitHub Enterprise API URL must not contain credentials.")
    hostname = clean_value(parsed.hostname).lower()
    allowed_hosts = allowed_github_hosts()
    if allowed_hosts and hostname not in allowed_hosts and hostname != "api.github.com":
        raise ValueError("GitHub Enterprise API URL host is not allowed by configuration.")
    if hostname == "api.github.com":
        return DEFAULT_GITHUB_API_URL
    path = parsed.path.rstrip("/")
    if not path.endswith("/api/v3"):
        path = f"{path}/api/v3"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def normalize_github_owner(value: Any) -> str:
    text = clean_value(value).strip().rstrip("/")
    if not text:
        return ""
    if "://" in text or text.lower().startswith("github.com/"):
        candidate = text if "://" in text else f"https://{text}"
        parsed = urlparse(candidate)
        if parsed.hostname and parsed.hostname.lower() not in {"github.com", "www.github.com"}:
            raise ValueError("GitHub URL must use github.com.")
        segments = [segment for segment in parsed.path.split("/") if segment]
        text = segments[0] if segments else ""
    if not text or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", text):
        raise ValueError("GitHub URL must be a GitHub owner or github.com owner URL.")
    return text


def parse_github_urls(value: Any, default: str = "") -> tuple[str, ...]:
    values: list[Any] = []
    if isinstance(value, dict):
        values.append(value.get("url") or value.get("owner"))
    elif isinstance(value, (list, tuple, set)):
        values.extend(value)
    elif value is not None:
        text = clean_value(value)
        if text.startswith("["):
            try:
                decoded = json.loads(text)
            except ValueError as exc:
                raise ValueError("GitHub URLs must be valid JSON or one URL per line.") from exc
            return parse_github_urls(decoded, default=default)
        values.extend(part for part in re.split(r"[\n,]", text) if part.strip())
    if not values and default:
        values.append(default)
    result: list[str] = []
    seen: set[str] = set()
    for value_item in values:
        candidate = value_item.get("url") or value_item.get("owner") if isinstance(value_item, dict) else value_item
        owner = normalize_github_owner(candidate)
        if owner and owner.casefold() not in seen:
            result.append(owner)
            seen.add(owner.casefold())
    return tuple(result)


def insecure_provider_urls_allowed() -> bool:
    return env_flag("APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS", "APPSEC_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS")


def allowed_github_hosts() -> set[str]:
    values = os.getenv("APPLICATION_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS") or os.getenv("APPSEC_INVENTORY_SERVICE_ALLOWED_GITHUB_HOSTS") or ""
    return {value.strip().lower() for value in values.split(",") if value.strip()}


def github_env_value(*names: str) -> str:
    for name in names:
        value = clean_value(os.getenv(name))
        if value:
            return value
    return ""


def configured_github_api_url() -> str:
    value = github_env_value(
        "APPLICATION_INVENTORY_GITHUB_API_URL",
        "APPLICATION_INVENTORY_BASE_URL",
        "APPSEC_INVENTORY_GITHUB_API_URL",
        "APPSEC_SCAN_BASE_URL",
        "GITHUB_API_URL",
        "GHE_API_URL",
    )
    return normalize_github_api_url(value or DEFAULT_GITHUB_API_URL)


def configured_github_owners() -> tuple[str, ...]:
    value = github_env_value("APPLICATION_INVENTORY_GITHUB_URLS", "APPSEC_INVENTORY_GITHUB_URLS")
    return parse_github_urls(value)


def configured_github_app_id() -> str:
    return github_env_value(
        "APPLICATION_INVENTORY_GITHUB_APP_ID",
        "APPSEC_INVENTORY_GITHUB_APP_ID",
        "GITHUB_APP_ID",
        "GHE_APP_ID",
    )


def configured_github_installation_id() -> str:
    return github_env_value(
        "APPLICATION_INVENTORY_GITHUB_APP_INSTALLATION_ID",
        "APPSEC_INVENTORY_GITHUB_APP_INSTALLATION_ID",
        "GITHUB_APP_INSTALLATION_ID",
        "GHE_APP_INSTALLATION_ID",
    )


def parse_github_expiry(value: Any) -> float:
    if not isinstance(value, str) or not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).timestamp()
    except ValueError:
        return 0.0


def env_flag(*names: str) -> bool:
    for name in names:
        if clean_value(os.getenv(name)).lower() in {"1", "true", "yes", "on"}:
            return True
    return False
