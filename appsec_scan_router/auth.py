from __future__ import annotations

import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from .constants import MISSING_CRYPTOGRAPHY_MESSAGE, MISSING_REQUESTS_MESSAGE
from .utils import clean_value

try:
    import requests
except ImportError:
    requests = None

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    Fernet = None
    InvalidToken = Exception


SESSION_COOKIE_NAME = "appsec_inventory_session"
SESSION_TTL_SECONDS = 43200
OAUTH_STATE_TTL_SECONDS = 600
PROVIDER_NAMES = ("azure-devops", "github-enterprise")


@dataclass(frozen=True)
class AuthenticatedUser:
    id: str
    login: str
    name: str = ""
    avatar_url: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "id": self.id,
            "login": self.login,
            "name": self.name,
            "avatarUrl": self.avatar_url,
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

    @classmethod
    def from_env(cls) -> "GitHubOAuthConfig":
        return cls(
            client_id=clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_GITHUB_CLIENT_ID")),
            client_secret=clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_GITHUB_CLIENT_SECRET")),
            authorize_url=clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_GITHUB_AUTHORIZE_URL"))
            or cls.authorize_url,
            token_url=clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_GITHUB_TOKEN_URL")) or cls.token_url,
            user_url=clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_GITHUB_USER_URL")) or cls.user_url,
            scope=clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_GITHUB_SCOPE")) or cls.scope,
        )

    @property
    def enabled(self) -> bool:
        return bool(self.client_id and self.client_secret)


class CredentialStore:
    def __init__(self, state_dir: Path) -> None:
        if Fernet is None:
            raise SystemExit(MISSING_CRYPTOGRAPHY_MESSAGE)
        self.state_dir = state_dir
        self.key_path = self.state_dir / "vault.key"
        self.credentials_path = self.state_dir / "credentials.json.enc"
        self.lock = threading.RLock()
        self.fernet = Fernet(self.encryption_key())

    def encryption_key(self) -> bytes:
        env_key = clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_SECRET_KEY"))
        if env_key:
            return env_key.encode("utf-8")
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        chmod_private(self.state_dir, 0o700)
        if self.key_path.exists():
            return self.key_path.read_bytes().strip()
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        chmod_private(self.key_path, 0o600)
        return key

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
                return {provider: False for provider in PROVIDER_NAMES}
            return {
                provider: bool(isinstance(credentials.get(provider), dict) and credentials[provider].get("token"))
                for provider in PROVIDER_NAMES
            }

    def read_data(self) -> dict[str, Any]:
        if not self.credentials_path.exists():
            return {"version": 1, "users": {}}
        try:
            plaintext = self.fernet.decrypt(self.credentials_path.read_bytes())
            data = json.loads(plaintext.decode("utf-8"))
        except (InvalidToken, OSError, ValueError):
            return {"version": 1, "users": {}}
        return data if isinstance(data, dict) else {"version": 1, "users": {}}

    def write_data(self, data: dict[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        chmod_private(self.state_dir, 0o700)
        payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.credentials_path.write_bytes(self.fernet.encrypt(payload))
        chmod_private(self.credentials_path, 0o600)


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
    def __init__(self, config: GitHubOAuthConfig) -> None:
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
            raise ValueError("GitHub login is not configured.")
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
        if not self.consume_state(state):
            raise ValueError("GitHub login expired. Try signing in again.")
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
                    "redirect_uri": redirect_uri,
                },
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise ValueError(f"GitHub login failed while exchanging the authorization code: {exc}") from exc
        except ValueError as exc:
            raise ValueError("GitHub login returned an invalid token response.") from exc
        token = clean_value(data.get("access_token")) if isinstance(data, dict) else ""
        if not token:
            raise ValueError("GitHub login did not return an access token.")
        return token

    def fetch_user(self, access_token: str) -> AuthenticatedUser:
        try:
            response = requests.get(
                self.config.user_url,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": f"Bearer {access_token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "appsec-inventory-service/1.5",
                },
                timeout=20,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            raise ValueError(f"GitHub login failed while loading the user profile: {exc}") from exc
        except ValueError as exc:
            raise ValueError("GitHub login returned an invalid user profile.") from exc
        user_id = clean_value(data.get("id")) if isinstance(data, dict) else ""
        login = clean_value(data.get("login")) if isinstance(data, dict) else ""
        if not user_id or not login:
            raise ValueError("GitHub login returned an incomplete user profile.")
        return AuthenticatedUser(
            id=user_id,
            login=login,
            name=clean_value(data.get("name")),
            avatar_url=clean_value(data.get("avatar_url")),
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
        self.oauth = GitHubOAuthService(GitHubOAuthConfig.from_env())
        self.credentials = CredentialStore(auth_state_dir(reports_root))

    def session(self, cookie_header: str) -> SessionRecord | None:
        return self.sessions.get(cookie_value(cookie_header, SESSION_COOKIE_NAME))

    def create_session(self, user: AuthenticatedUser) -> SessionRecord:
        return self.sessions.create(user)

    def logout(self, session_id: str) -> None:
        self.sessions.delete(session_id)

    def status(self, record: SessionRecord | None) -> dict[str, Any]:
        credentials = self.credentials.statuses(record.user.id) if record else {
            provider: False for provider in PROVIDER_NAMES
        }
        return {
            "loggedIn": bool(record),
            "user": record.user.as_dict() if record else None,
            "csrfToken": record.csrf_token if record else "",
            "githubLoginEnabled": self.oauth.enabled,
            "credentials": credentials,
        }

    def apply_credentials(self, payload: dict[str, Any], record: SessionRecord | None) -> dict[str, Any]:
        provider = provider_name(payload.get("provider", "azure-devops"))
        token = clean_value(payload.get("token"))
        save_token = bool(payload.get("saveToken"))
        if save_token and not record:
            raise ValueError("Sign in with GitHub before saving provider tokens.")
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
            raise ValueError("Sign in with GitHub before managing saved tokens.")
        self.credentials.delete_token(record.user.id, provider)


def auth_state_dir(reports_root: Path) -> Path:
    configured = clean_value(os.getenv("APPSEC_INVENTORY_SERVICE_STATE_DIR"))
    return Path(configured).expanduser() if configured else reports_root / ".appsec_inventory_service"


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


def expired_session_cookie() -> str:
    return f"{SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"


def chmod_private(path: Path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        return


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
