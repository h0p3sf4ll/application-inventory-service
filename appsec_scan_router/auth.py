from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, urlunparse

from .constants import MISSING_REQUESTS_MESSAGE
from .secure_store import EncryptedJsonStore
from .utils import clean_value

try:
    import requests
except ImportError:
    requests = None

SESSION_COOKIE_NAME = "application_inventory_session"
SESSION_TTL_SECONDS = 43200
OAUTH_STATE_TTL_SECONDS = 600
PROVIDER_NAMES = ("azure-devops", "github-enterprise")
TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
FALSE_VALUES = frozenset({"0", "false", "no", "off"})


@dataclass(frozen=True)
class AuthenticatedUser:
    id: str
    login: str
    name: str = ""
    avatar_url: str = ""
    provider: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "login": self.login,
            "name": self.name,
            "avatarUrl": self.avatar_url,
            "provider": self.provider,
        }


@dataclass(frozen=True)
class SessionRecord:
    id: str
    user: AuthenticatedUser
    csrf_token: str
    expires_at: float

    def active(self, now: float | None = None) -> bool:
        return self.expires_at > (now or time.time())


@dataclass(frozen=True)
class GitHubOAuthConfig:
    client_id: str
    client_secret: str
    authorize_url: str = "https://github.com/login/oauth/authorize"
    token_url: str = "https://github.com/login/oauth/access_token"
    user_url: str = "https://api.github.com/user"
    scope: str = "read:user"

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)


@dataclass(frozen=True)
class GitHubEnterpriseOAuthConfig(GitHubOAuthConfig):
    @classmethod
    def from_env(cls) -> GitHubEnterpriseOAuthConfig:
        base_url = env_value(
            "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_BASE_URL",
            "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_BASE_URL",
            "APPLICATION_INVENTORY_SERVICE_GHE_BASE_URL",
            "APPSEC_INVENTORY_SERVICE_GHE_BASE_URL",
            "GITHUB_ENTERPRISE_BASE_URL",
            "GHE_BASE_URL",
        )
        origin = enterprise_oauth_origin(base_url)
        authorize_url = env_value(
            "APPLICATION_INVENTORY_SERVICE_GHE_AUTHORIZE_URL",
            "APPSEC_INVENTORY_SERVICE_GHE_AUTHORIZE_URL",
            "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_AUTHORIZE_URL",
            "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_AUTHORIZE_URL",
        )
        token_url = env_value(
            "APPLICATION_INVENTORY_SERVICE_GHE_TOKEN_URL",
            "APPSEC_INVENTORY_SERVICE_GHE_TOKEN_URL",
            "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_TOKEN_URL",
            "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_TOKEN_URL",
        )
        user_url = env_value(
            "APPLICATION_INVENTORY_SERVICE_GHE_USER_URL",
            "APPSEC_INVENTORY_SERVICE_GHE_USER_URL",
            "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_USER_URL",
            "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_USER_URL",
        )
        return cls(
            client_id=env_value(
                "APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_ID",
                "APPSEC_INVENTORY_SERVICE_GHE_CLIENT_ID",
                "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_CLIENT_ID",
                "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_CLIENT_ID",
            ),
            client_secret=env_value(
                "APPLICATION_INVENTORY_SERVICE_GHE_CLIENT_SECRET",
                "APPSEC_INVENTORY_SERVICE_GHE_CLIENT_SECRET",
                "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_CLIENT_SECRET",
                "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_CLIENT_SECRET",
            ),
            authorize_url=valid_oauth_endpoint((authorize_url or f"{origin}/login/oauth/authorize") if origin else authorize_url),
            token_url=valid_oauth_endpoint((token_url or f"{origin}/login/oauth/access_token") if origin else token_url),
            user_url=valid_oauth_endpoint((user_url or f"{origin}/api/v3/user") if origin else user_url),
            scope=env_value(
                "APPLICATION_INVENTORY_SERVICE_GHE_SCOPE",
                "APPSEC_INVENTORY_SERVICE_GHE_SCOPE",
                "APPLICATION_INVENTORY_SERVICE_GITHUB_ENTERPRISE_SCOPE",
                "APPSEC_INVENTORY_SERVICE_GITHUB_ENTERPRISE_SCOPE",
            )
            or "read:user read:org",
        )

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret and self.authorize_url and self.token_url and self.user_url)


@dataclass(frozen=True)
class GoogleOAuthConfig:
    client_id: str
    client_secret: str
    authorize_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: str = "https://oauth2.googleapis.com/token"
    user_url: str = "https://openidconnect.googleapis.com/v1/userinfo"
    scope: str = "openid email profile"

    @classmethod
    def from_env(cls) -> GoogleOAuthConfig:
        return cls(
            client_id=env_value("APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_ID", "APPSEC_INVENTORY_SERVICE_GOOGLE_CLIENT_ID"),
            client_secret=env_value("APPLICATION_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET", "APPSEC_INVENTORY_SERVICE_GOOGLE_CLIENT_SECRET"),
            authorize_url=env_value("APPLICATION_INVENTORY_SERVICE_GOOGLE_AUTHORIZE_URL", "APPSEC_INVENTORY_SERVICE_GOOGLE_AUTHORIZE_URL")
            or cls.authorize_url,
            token_url=env_value("APPLICATION_INVENTORY_SERVICE_GOOGLE_TOKEN_URL", "APPSEC_INVENTORY_SERVICE_GOOGLE_TOKEN_URL") or cls.token_url,
            user_url=env_value("APPLICATION_INVENTORY_SERVICE_GOOGLE_USER_URL", "APPSEC_INVENTORY_SERVICE_GOOGLE_USER_URL") or cls.user_url,
            scope=env_value("APPLICATION_INVENTORY_SERVICE_GOOGLE_SCOPE", "APPSEC_INVENTORY_SERVICE_GOOGLE_SCOPE") or cls.scope,
        )

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)


@dataclass(frozen=True)
class TestLoginConfig:
    enabled: bool
    user_id: str = "test-user"
    login: str = "test.user@local"
    name: str = "Test User"

    @classmethod
    def from_env(cls) -> TestLoginConfig:
        return cls(
            enabled=test_login_enabled_from_env(),
            user_id=env_value("APPLICATION_INVENTORY_SERVICE_TEST_USER_ID", "APPSEC_INVENTORY_SERVICE_TEST_USER_ID") or cls.user_id,
            login=env_value("APPLICATION_INVENTORY_SERVICE_TEST_USER_LOGIN", "APPSEC_INVENTORY_SERVICE_TEST_USER_LOGIN") or cls.login,
            name=env_value("APPLICATION_INVENTORY_SERVICE_TEST_USER_NAME", "APPSEC_INVENTORY_SERVICE_TEST_USER_NAME") or cls.name,
        )

    def user(self) -> AuthenticatedUser:
        return AuthenticatedUser(
            id=self.user_id,
            login=self.login,
            name=self.name,
            provider="test",
        )


class CredentialStore:
    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.lock = threading.RLock()
        self.store = EncryptedJsonStore(state_dir, "credentials.json.enc", self.default_data)
        self.key_path = self.store.key_path
        self.credentials_path = self.store.path
        self.fernet = self.store.fernet

    def save_token(self, user_id: str, provider: str, token: str) -> None:
        clean_provider = provider_name(provider)
        clean_token = clean_value(token)
        if not clean_token:
            return
        with self.lock:
            data = self.read_data()
            users = data.setdefault("users", {})
            credentials = users.setdefault(clean_value(user_id), {})
            credentials[clean_provider] = {
                "token": clean_token,
                "updatedAt": utc_timestamp(),
            }
            self.write_data(data)

    def token(self, user_id: str, provider: str) -> str:
        clean_provider = provider_name(provider)
        with self.lock:
            credentials = self.read_data().get("users", {}).get(clean_value(user_id), {})
            entry = credentials.get(clean_provider, {})
            return clean_value(entry.get("token")) if isinstance(entry, dict) else ""

    def delete_token(self, user_id: str, provider: str) -> None:
        clean_provider = provider_name(provider)
        with self.lock:
            data = self.read_data()
            credentials = data.get("users", {}).get(clean_value(user_id), {})
            if isinstance(credentials, dict):
                credentials.pop(clean_provider, None)
            self.write_data(data)

    def statuses(self, user_id: str) -> dict[str, bool]:
        with self.lock:
            credentials = self.read_data().get("users", {}).get(clean_value(user_id), {})
            if not isinstance(credentials, dict):
                return dict.fromkeys(PROVIDER_NAMES, False)
            return {
                provider: bool(isinstance(credentials.get(provider), dict) and credentials[provider].get("token"))
                for provider in PROVIDER_NAMES
            }

    def read_data(self) -> dict[str, Any]:
        return self.store.read()

    def write_data(self, data: dict[str, Any]) -> None:
        self.store.write(data)

    @staticmethod
    def default_data() -> dict[str, Any]:
        return {"version": 1, "users": {}}


class SessionStore:
    def __init__(self) -> None:
        self.sessions: dict[str, SessionRecord] = {}
        self.lock = threading.RLock()

    def create(self, user: AuthenticatedUser) -> SessionRecord:
        record = SessionRecord(
            id=secrets.token_urlsafe(32),
            user=user,
            csrf_token=secrets.token_urlsafe(32),
            expires_at=time.time() + SESSION_TTL_SECONDS,
        )
        with self.lock:
            self.sessions[record.id] = record
        return record

    def get(self, session_id: str) -> SessionRecord | None:
        with self.lock:
            record = self.sessions.get(clean_value(session_id))
            if not record:
                return None
            if not record.active():
                self.sessions.pop(record.id, None)
                return None
            return record

    def delete(self, session_id: str) -> None:
        with self.lock:
            self.sessions.pop(clean_value(session_id), None)


class GitHubOAuthService:
    def __init__(self, config: GitHubOAuthConfig, provider: str = "github", display_name: str = "GitHub") -> None:
        if requests is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)
        self.config = config
        self.provider = provider
        self.display_name = display_name
        self.states: dict[str, float] = {}
        self.lock = threading.RLock()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def authorization_url(self, redirect_uri: str) -> str:
        if not self.enabled:
            raise ValueError(f"{self.display_name} login is not configured.")
        state = secrets.token_urlsafe(32)
        with self.lock:
            self.states[state] = time.time() + OAUTH_STATE_TTL_SECONDS
            self.prune_states()
        query = urlencode(
            {
                "client_id": self.config.client_id,
                "redirect_uri": redirect_uri,
                "scope": self.config.scope,
                "state": state,
            }
        )
        return f"{self.config.authorize_url}?{query}"

    def complete(self, code: str, state: str, redirect_uri: str) -> AuthenticatedUser:
        return self.complete_with_token(code, state, redirect_uri)[0]

    def complete_with_token(self, code: str, state: str, redirect_uri: str) -> tuple[AuthenticatedUser, str]:
        if not self.consume_state(state):
            raise ValueError(f"{self.display_name} login expired. Try signing in again.")
        access_token = self.exchange_code(code, redirect_uri)
        return self.fetch_user(access_token), access_token

    def exchange_code(self, code: str, redirect_uri: str) -> str:
        try:
            response = requests.post(
                self.config.token_url,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise ValueError(f"{self.display_name} login failed while exchanging the authorization code: {exc}") from exc
        except ValueError as exc:
            raise ValueError(f"{self.display_name} login returned an invalid token response.") from exc
        token = clean_value(data.get("access_token")) if isinstance(data, dict) else ""
        if not token:
            raise ValueError(f"{self.display_name} login did not return an access token.")
        return token

    def fetch_user(self, access_token: str) -> AuthenticatedUser:
        try:
            response = requests.get(
                self.config.user_url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {access_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "application-inventory-service/1.6.12",
                },
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise ValueError(f"{self.display_name} login failed while loading the user profile: {exc}") from exc
        except ValueError as exc:
            raise ValueError(f"{self.display_name} login returned an invalid user profile.") from exc
        user_id = clean_value(data.get("id")) if isinstance(data, dict) else ""
        login = clean_value(data.get("login")) if isinstance(data, dict) else ""
        if not user_id or not login:
            raise ValueError(f"{self.display_name} login returned an incomplete user profile.")
        return AuthenticatedUser(
            id=user_id,
            login=login,
            name=clean_value(data.get("name")),
            avatar_url=clean_value(data.get("avatar_url")),
            provider=self.provider,
        )

    def consume_state(self, state: str) -> bool:
        clean_state = clean_value(state)
        with self.lock:
            expires_at = self.states.pop(clean_state, 0)
        return bool(expires_at and expires_at > time.time())

    def prune_states(self) -> None:
        now = time.time()
        for state, expires_at in list(self.states.items()):
            if expires_at <= now:
                self.states.pop(state, None)


class GoogleOAuthService:
    def __init__(self, config: GoogleOAuthConfig) -> None:
        if requests is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)
        self.config = config
        self.states: dict[str, float] = {}
        self.lock = threading.RLock()

    @property
    def enabled(self) -> bool:
        return self.config.enabled

    def authorization_url(self, redirect_uri: str) -> str:
        if not self.enabled:
            raise ValueError("Google login is not configured.")
        state = secrets.token_urlsafe(32)
        with self.lock:
            self.states[state] = time.time() + OAUTH_STATE_TTL_SECONDS
            self.prune_states()
        query = urlencode(
            {
                "client_id": self.config.client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": self.config.scope,
                "state": state,
            }
        )
        return f"{self.config.authorize_url}?{query}"

    def complete(self, code: str, state: str, redirect_uri: str) -> AuthenticatedUser:
        if not self.consume_state(state):
            raise ValueError("Google login expired. Try signing in again.")
        access_token = self.exchange_code(code, redirect_uri)
        return self.fetch_user(access_token)

    def exchange_code(self, code: str, redirect_uri: str) -> str:
        try:
            response = requests.post(
                self.config.token_url,
                headers={"Accept": "application/json"},
                data={
                    "client_id": self.config.client_id,
                    "client_secret": self.config.client_secret,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": redirect_uri,
                },
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise ValueError(f"Google login failed while exchanging the authorization code: {exc}") from exc
        except ValueError as exc:
            raise ValueError("Google login returned an invalid token response.") from exc
        token = clean_value(data.get("access_token")) if isinstance(data, dict) else ""
        if not token:
            raise ValueError("Google login did not return an access token.")
        return token

    def fetch_user(self, access_token: str) -> AuthenticatedUser:
        try:
            response = requests.get(
                self.config.user_url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                    "User-Agent": "application-inventory-service/1.6.12",
                },
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise ValueError(f"Google login failed while loading the user profile: {exc}") from exc
        except ValueError as exc:
            raise ValueError("Google login returned an invalid user profile.") from exc
        subject = clean_value(data.get("sub")) if isinstance(data, dict) else ""
        email = clean_value(data.get("email")) if isinstance(data, dict) else ""
        if not subject:
            raise ValueError("Google login returned an incomplete user profile.")
        return AuthenticatedUser(
            id=f"google:{subject}",
            login=email or subject,
            name=clean_value(data.get("name")),
            avatar_url=clean_value(data.get("picture")),
            provider="google",
        )

    def consume_state(self, state: str) -> bool:
        clean_state = clean_value(state)
        with self.lock:
            expires_at = self.states.pop(clean_state, 0)
        return bool(expires_at and expires_at > time.time())

    def prune_states(self) -> None:
        now = time.time()
        for state, expires_at in list(self.states.items()):
            if expires_at <= now:
                self.states.pop(state, None)


class AuthManager:
    def __init__(self, reports_root: Path) -> None:
        self.sessions = SessionStore()
        self.github_enterprise_oauth = GitHubOAuthService(
            GitHubEnterpriseOAuthConfig.from_env(),
            provider="github-enterprise",
            display_name="GitHub Enterprise",
        )
        self.google_oauth = GoogleOAuthService(GoogleOAuthConfig.from_env())
        self.test_login = TestLoginConfig.from_env()
        self.credentials = CredentialStore(auth_state_dir(reports_root))

    def session(self, cookie_header: str) -> SessionRecord | None:
        return self.sessions.get(cookie_value(cookie_header, SESSION_COOKIE_NAME))

    def create_session(self, user: AuthenticatedUser, provider_token: str = "") -> SessionRecord:
        record = self.sessions.create(user)
        if provider_token and user.provider in PROVIDER_NAMES:
            self.credentials.save_token(user.id, user.provider, provider_token)
        return record

    def logout(self, session_id: str) -> None:
        self.sessions.delete(session_id)

    def status(self, record: SessionRecord | None) -> dict[str, Any]:
        credentials = self.credentials.statuses(record.user.id) if record else dict.fromkeys(PROVIDER_NAMES, False)
        return {
            "loggedIn": bool(record),
            "user": record.user.as_dict() if record else None,
            "csrfToken": record.csrf_token if record else "",
            "githubEnterpriseLoginEnabled": self.github_enterprise_oauth.enabled,
            "googleLoginEnabled": self.google_oauth.enabled,
            "testLoginEnabled": self.test_login.enabled,
            "authProviders": [
                {
                    "id": "github-enterprise",
                    "label": "GitHub Enterprise",
                    "enabled": self.github_enterprise_oauth.enabled,
                    "startUrl": "/api/auth/github-enterprise/start",
                },
                {
                    "id": "google",
                    "label": "Google SSO",
                    "enabled": self.google_oauth.enabled,
                    "startUrl": "/api/auth/google/start",
                },
                {
                    "id": "test",
                    "label": "Test User",
                    "enabled": self.test_login.enabled,
                    "startUrl": "/api/auth/test/start",
                },
            ],
            "credentials": credentials,
        }

    def create_test_session(self) -> SessionRecord:
        if not self.test_login.enabled:
            raise ValueError("Test user login is not enabled.")
        return self.create_session(self.test_login.user())

    def apply_credentials(self, payload: dict[str, Any], record: SessionRecord | None) -> dict[str, Any]:
        requested_provider = clean_value(payload.get("provider", "azure-devops"))
        provider = "github-enterprise" if requested_provider == "mixed" else provider_name(requested_provider)
        token = clean_value(payload.get("token"))
        save_token = bool(payload.get("saveToken"))
        if save_token and not record:
            raise ValueError("Sign in before saving provider tokens.")
        if token and save_token and record:
            self.credentials.save_token(record.user.id, provider, token)
        if not token and record:
            saved_token = self.credentials.token(record.user.id, provider)
            if saved_token:
                payload = dict(payload)
                payload["token"] = saved_token
        return payload

    def delete_credential(self, provider: str, record: SessionRecord | None) -> None:
        if not record:
            raise ValueError("Sign in before managing saved tokens.")
        self.credentials.delete_token(record.user.id, provider)


def auth_state_dir(reports_root: Path) -> Path:
    configured = env_value("APPLICATION_INVENTORY_SERVICE_STATE_DIR", "APPSEC_INVENTORY_SERVICE_STATE_DIR")
    return Path(configured).expanduser() if configured else reports_root / ".application_inventory_service"


def test_login_enabled_from_env(default: bool = True) -> bool:
    value = env_value("APPLICATION_INVENTORY_SERVICE_TEST_LOGIN_ENABLED", "APPSEC_INVENTORY_SERVICE_TEST_LOGIN_ENABLED").strip().lower()
    if not value:
        return default
    if value in TRUE_VALUES:
        return True
    if value in FALSE_VALUES:
        return False
    return default


def env_value(*names: str) -> str:
    for name in names:
        value = clean_value(os.getenv(name))
        if value:
            return value
    return ""


def enterprise_oauth_origin(value: str) -> str:
    raw_value = clean_value(value)
    if not raw_value:
        return ""
    parsed = urlparse(raw_value if "://" in raw_value else f"https://{raw_value}")
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return ""
    if parsed.scheme != "https" and not insecure_urls_allowed():
        return ""
    path = parsed.path.rstrip("/")
    if path.endswith("/api/v3"):
        path = path[: -len("/api/v3")].rstrip("/")
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", "")).rstrip("/")


def valid_oauth_endpoint(value: str) -> str:
    raw_value = clean_value(value)
    if not raw_value:
        return ""
    parsed = urlparse(raw_value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        return ""
    if parsed.scheme != "https" and not insecure_urls_allowed():
        return ""
    return raw_value.rstrip("/")


def insecure_urls_allowed() -> bool:
    return env_value(
        "APPLICATION_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS",
        "APPSEC_INVENTORY_SERVICE_ALLOW_INSECURE_PROVIDER_URLS",
    ).lower() in TRUE_VALUES


def provider_name(value: Any) -> str:
    provider = clean_value(value)
    if provider not in PROVIDER_NAMES:
        raise ValueError("Unknown provider.")
    return provider


def cookie_value(cookie_header: str, name: str) -> str:
    for part in clean_value(cookie_header).split(";"):
        key, separator, value = part.strip().partition("=")
        if separator and key == name:
            return value
    return ""


def session_cookie(session_id: str, secure: bool = False) -> str:
    parts = [
        f"{SESSION_COOKIE_NAME}={session_id}",
        "Path=/",
        f"Max-Age={SESSION_TTL_SECONDS}",
        "HttpOnly",
        "SameSite=Lax",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def expired_session_cookie(secure: bool = False) -> str:
    parts = [
        f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0",
        "HttpOnly",
        "SameSite=Lax",
    ]
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
