from __future__ import annotations

import base64
from email.utils import parsedate_to_datetime
import logging
import os
import threading
import time
from collections.abc import Iterator
from typing import Any

from .constants import API_VERSION, DEFAULT_COMMIT_PAGE_SIZE, MISSING_REQUESTS_MESSAGE
from .models import AzureDevOpsError

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None


LOGGER = logging.getLogger("appsec_scan_router")
DEFAULT_ADO_REQUESTS_PER_SECOND = 6.0
DEFAULT_ADO_POOL_SIZE = 4
DEFAULT_ADO_MAX_RETRIES = 8
DEFAULT_ADO_LOW_REMAINING_BACKOFF_SECONDS = 2.0


class AzureDevOpsClient:
    def __init__(self, org: str, pat: str, timeout_seconds: int) -> None:
        if requests is None or HTTPAdapter is None or Retry is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)

        self.org = org
        self.timeout_seconds = timeout_seconds
        self._pool_size = positive_int_env("APPLICATION_INVENTORY_ADO_POOL_SIZE", DEFAULT_ADO_POOL_SIZE)
        self._throttle = AzureDevOpsThrottle(
            requests_per_second=positive_float_env(
                "APPLICATION_INVENTORY_ADO_REQUESTS_PER_SECOND",
                DEFAULT_ADO_REQUESTS_PER_SECOND,
            ),
            low_remaining_backoff_seconds=positive_float_env(
                "APPLICATION_INVENTORY_ADO_LOW_REMAINING_BACKOFF_SECONDS",
                DEFAULT_ADO_LOW_REMAINING_BACKOFF_SECONDS,
            ),
        )
        self._headers = {
            "Authorization": self._auth_header_value(pat),
            "Accept": "application/json",
            "User-Agent": "application-inventory-service/1.6.14",
        }
        self._retry = Retry(
            total=positive_int_env("APPLICATION_INVENTORY_ADO_MAX_RETRIES", DEFAULT_ADO_MAX_RETRIES),
            connect=2,
            read=3,
            other=0,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )
        self._thread_local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()

    @staticmethod
    def _auth_header_value(pat: str) -> str:
        token = base64.b64encode(f":{pat}".encode()).decode("ascii")
        return f"Basic {token}"

    def close(self) -> None:
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
            adapter = HTTPAdapter(
                max_retries=self._retry,
                pool_connections=self._pool_size,
                pool_maxsize=self._pool_size,
                pool_block=True,
            )
            session.mount("https://", adapter)
            self._thread_local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def _url(self, path: str) -> str:
        return f"https://dev.azure.com/{self.org}{path}"

    def get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = self._url(path)
        try:
            self._throttle.wait()
            response = self.session.get(url, params=self._with_api_version(params), timeout=self.timeout_seconds)
            self._throttle.observe(response)
            return response
        except requests.RequestException as exc:
            raise AzureDevOpsError(provider_connection_message("Azure DevOps", url, exc)) from exc

    def get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self.get(path, params)
        self._raise_for_status(response)
        try:
            data = response.json()
        except ValueError as exc:
            raise AzureDevOpsError(f"Expected JSON from {response.url}") from exc
        if not isinstance(data, dict):
            raise AzureDevOpsError(f"Expected JSON object from {response.url}")
        return data

    def get_text_or_content(self, path: str, params: dict[str, Any] | None = None) -> str:
        response = self.get(path, params)
        self._raise_for_status(response)

        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                data = response.json()
            except ValueError:
                return response.text
            if isinstance(data, dict):
                content = data.get("content")
                if isinstance(content, str):
                    return content
        return response.text

    @staticmethod
    def _with_api_version(params: dict[str, Any] | None) -> dict[str, Any]:
        merged = {"api-version": API_VERSION}
        if params:
            merged.update(params)
        return merged

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

    def list_projects(self) -> list[dict[str, Any]]:
        projects: list[dict[str, Any]] = []
        continuation: str | None = None

        while True:
            params: dict[str, Any] = {"$top": 100}
            if continuation:
                params["continuationToken"] = continuation

            response = self.get("/_apis/projects", params)
            self._raise_for_status(response)
            projects.extend(response.json().get("value", []))

            continuation = response.headers.get("x-ms-continuationtoken")
            if not continuation:
                return projects

    def list_repos(self, project_name: str) -> list[dict[str, Any]]:
        data = self.get_json(f"/{project_name}/_apis/git/repositories")
        return data.get("value", [])

    def list_branches(self, project_name: str, repo_id: str) -> list[dict[str, Any]]:
        refs: list[dict[str, Any]] = []
        continuation: str | None = None

        while True:
            params: dict[str, Any] = {"filter": "heads/", "$top": 1000}
            if continuation:
                params["continuationToken"] = continuation

            response = self.get(f"/{project_name}/_apis/git/repositories/{repo_id}/refs", params)
            self._raise_for_status(response)
            refs.extend(response.json().get("value", []))

            continuation = response.headers.get("x-ms-continuationtoken")
            if not continuation:
                return refs

    def list_build_definitions_for_repo(self, project_name: str, repo_id: str) -> list[dict[str, Any]]:
        definitions: list[dict[str, Any]] = []
        continuation: str | None = None

        while True:
            params: dict[str, Any] = {
                "repositoryId": repo_id,
                "repositoryType": "TfsGit",
                "includeAllProperties": "true",
                "$top": 100,
            }
            if continuation:
                params["continuationToken"] = continuation

            response = self.get(f"/{project_name}/_apis/build/definitions", params)
            self._raise_for_status(response)
            definitions.extend(response.json().get("value", []))

            continuation = response.headers.get("x-ms-continuationtoken")
            if not continuation:
                return definitions

    def list_repo_items(self, project_name: str, repo_id: str, branch_name: str | None = None) -> list[dict[str, Any]]:
        params = {
            "recursionLevel": "Full",
            "scopePath": "/",
            "includeContentMetadata": "false",
        }
        params.update(self._branch_version_params(branch_name))
        data = self.get_json(
            f"/{project_name}/_apis/git/repositories/{repo_id}/items",
            params,
        )
        return data.get("value", [])

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
        continuation: str | None = None
        skip = 0
        yielded = 0
        seen_first_commit_ids: set[str] = set()

        while True:
            remaining = max_commits - yielded if max_commits else page_size
            top = min(page_size, remaining) if max_commits else page_size
            if top <= 0:
                break

            params: dict[str, Any] = {"searchCriteria.$top": top}
            params.update(self._branch_commit_params(branch_name))
            if continuation:
                params["continuationToken"] = continuation
            elif skip:
                params["searchCriteria.$skip"] = skip

            response = self.get(f"/{project_name}/_apis/git/repositories/{repo_id}/commits", params)
            self._raise_for_status(response)
            batch = response.json().get("value", [])
            if not batch:
                break

            first_commit_id = str(batch[0].get("commitId", ""))
            if first_commit_id and first_commit_id in seen_first_commit_ids:
                LOGGER.debug("Stopping commit pagination for repo %s after repeated page.", repo_id)
                break
            if first_commit_id:
                seen_first_commit_ids.add(first_commit_id)

            for commit in batch:
                if not isinstance(commit, dict):
                    continue
                yield commit
                yielded += 1
                if max_commits and yielded >= max_commits:
                    return

            continuation = response.headers.get("x-ms-continuationtoken")
            if continuation:
                continue
            if len(batch) < top:
                break
            skip += len(batch)

        return

    def fetch_file_content(
        self,
        project_name: str,
        repo_id: str,
        file_path: str,
        branch_name: str | None = None,
    ) -> str:
        params = {
            "path": file_path,
            "includeContent": "true",
        }
        params.update(self._branch_version_params(branch_name))
        try:
            return self.get_text_or_content(
                f"/{project_name}/_apis/git/repositories/{repo_id}/items",
                params,
            )
        except (AzureDevOpsError, requests.RequestException) as exc:
            LOGGER.debug("Failed to fetch %s in repo %s: %s", file_path, repo_id, exc)
            return ""

    @staticmethod
    def _branch_version_params(branch_name: str | None) -> dict[str, Any]:
        if not branch_name:
            return {}
        return {
            "versionDescriptor.version": branch_name,
            "versionDescriptor.versionType": "branch",
        }

    @staticmethod
    def _branch_commit_params(branch_name: str | None) -> dict[str, Any]:
        if not branch_name:
            return {}
        return {
            "searchCriteria.itemVersion.version": branch_name,
            "searchCriteria.itemVersion.versionType": "branch",
        }


def provider_connection_message(provider: str, url: str, exc: Exception) -> str:
    return (
        f"{provider} connection failed for {url}: {exc}. "
        "Check DNS, VPN/proxy access, container network settings, and whether the provider host is reachable."
    )


class AzureDevOpsThrottle:
    def __init__(self, requests_per_second: float, low_remaining_backoff_seconds: float) -> None:
        self.min_interval_seconds = 0.0 if requests_per_second <= 0 else 1.0 / requests_per_second
        self.low_remaining_backoff_seconds = low_remaining_backoff_seconds
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
            base = max(scheduled_at, now)
            self.next_request_at = base + self.min_interval_seconds
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

    def observe(self, response: requests.Response) -> None:
        retry_after = retry_after_seconds(response.headers.get("Retry-After"))
        if retry_after > 0:
            self.defer(retry_after)
            LOGGER.info("Azure DevOps requested %.2fs client backoff.", retry_after)
            return

        if response.status_code == 429:
            self.defer(max(self.low_remaining_backoff_seconds, self.min_interval_seconds * 4))
            return

        remaining = float_header(response.headers.get("X-RateLimit-Remaining"))
        if remaining is not None and remaining <= 1:
            self.defer(self.low_remaining_backoff_seconds)

    def defer(self, seconds: float) -> None:
        if seconds <= 0:
            return
        with self.lock:
            self.block_until = max(self.block_until, time.monotonic() + seconds)


def positive_float_env(name: str, default: float) -> float:
    raw_value = os.getenv(name)
    if not raw_value:
        return default
    try:
        value = float(raw_value)
    except ValueError:
        return default
    return value if value >= 0 else default


def positive_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        return default
    return value if value > 0 else default


def retry_after_seconds(value: str | None) -> float:
    if not value:
        return 0.0
    cleaned = value.strip()
    try:
        return max(0.0, float(cleaned))
    except ValueError:
        pass
    try:
        retry_at = parsedate_to_datetime(cleaned)
    except (TypeError, ValueError, IndexError, OverflowError):
        return 0.0
    return max(0.0, retry_at.timestamp() - time.time())


def float_header(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
