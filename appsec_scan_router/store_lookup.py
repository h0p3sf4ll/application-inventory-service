from __future__ import annotations

import logging
import re
import threading
from html import unescape
from html.parser import HTMLParser
from collections.abc import Callable, Iterable

from .constants import MISSING_REQUESTS_MESSAGE
from .models import StoreListing
from .utils import clean_value

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None
    HTTPAdapter = None
    Retry = None


LOGGER = logging.getLogger("appsec_scan_router")

APPLE_PLATFORM = "apple_app_store"
GOOGLE_PLATFORM = "google_play"
APPLE_DISPLAY_NAME = "Apple App Store"
GOOGLE_DISPLAY_NAME = "Google Play"
CROSS_PLATFORM_CATEGORIES = frozenset({"flutter", "react_native", "ionic_capacitor_cordova", "xamarin_maui"})
BOTH_STORE_PLATFORMS = (APPLE_PLATFORM, GOOGLE_PLATFORM)
STORE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*(?:\.[A-Za-z0-9][A-Za-z0-9_-]*)+$")


class StoreLookupClient:
    def __init__(self, country: str, timeout_seconds: int) -> None:
        if requests is None or HTTPAdapter is None or Retry is None:
            raise SystemExit(MISSING_REQUESTS_MESSAGE)

        self.country = clean_value(country).upper() or "US"
        self.timeout_seconds = timeout_seconds
        self._thread_local = threading.local()
        self._sessions: list[requests.Session] = []
        self._sessions_lock = threading.Lock()
        self._cache: dict[tuple[str, str], StoreListing] = {}
        self._cache_lock = threading.Lock()
        self._retry = Retry(
            total=3,
            connect=0,
            read=0,
            other=0,
            status=3,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
            respect_retry_after_header=True,
        )

    @property
    def session(self) -> requests.Session:
        session = getattr(self._thread_local, "session", None)
        if session is None:
            session = requests.Session()
            session.headers.update(
                {
                    "Accept": "application/json,text/html,application/xhtml+xml",
                    "User-Agent": "application-inventory-service/1.6.3",
                }
            )
            adapter = HTTPAdapter(max_retries=self._retry, pool_connections=8, pool_maxsize=8)
            session.mount("https://", adapter)
            self._thread_local.session = session
            with self._sessions_lock:
                self._sessions.append(session)
        return session

    def close(self) -> None:
        with self._sessions_lock:
            for session in self._sessions:
                session.close()
            self._sessions.clear()

    def lookup(self, identifier: str, categories: Iterable[str]) -> list[StoreListing]:
        cleaned_identifier = clean_value(identifier)
        if not cleaned_identifier:
            return []
        return [
            self.lookup_platform(platform, cleaned_identifier)
            for platform in target_store_platforms(categories)
        ]

    def lookup_platform(self, platform: str, identifier: str) -> StoreListing:
        cache_key = (platform, identifier)
        with self._cache_lock:
            cached = self._cache.get(cache_key)
        if cached:
            return cached

        handlers: dict[str, Callable[[str], StoreListing]] = {
            APPLE_PLATFORM: self.lookup_apple_app_store,
            GOOGLE_PLATFORM: self.lookup_google_play,
        }
        handler = handlers.get(platform)
        listing = (
            handler(identifier)
            if handler
            else StoreListing(platform=platform, status="not_requested", identifier=identifier)
        )

        with self._cache_lock:
            self._cache[cache_key] = listing
        return listing

    def lookup_apple_app_store(self, identifier: str) -> StoreListing:
        try:
            response = self.session.get(
                "https://itunes.apple.com/lookup",
                params={
                    "bundleId": identifier,
                    "country": self.country,
                    "entity": "software",
                    "limit": 1,
                },
                timeout=self.timeout_seconds,
            )
            response.raise_for_status()
            data = response.json()
        except requests.exceptions.SSLError as exc:
            LOGGER.debug("Apple App Store TLS lookup failed for %s: %s", identifier, exc)
            return StoreListing(platform=APPLE_PLATFORM, status="tls_error", identifier=identifier, error=str(exc))
        except (requests.RequestException, ValueError) as exc:
            LOGGER.debug("Apple App Store lookup failed for %s: %s", identifier, exc)
            return StoreListing(platform=APPLE_PLATFORM, status="error", identifier=identifier, error=str(exc))

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or not results:
            return StoreListing(platform=APPLE_PLATFORM, status="not_found", identifier=identifier)

        result = results[0] if isinstance(results[0], dict) else {}
        return StoreListing(
            platform=APPLE_PLATFORM,
            status="found",
            name=clean_value(result.get("trackName")),
            identifier=clean_value(result.get("bundleId")) or identifier,
            url=clean_value(result.get("trackViewUrl")),
            version=clean_value(result.get("version")),
            last_updated=clean_value(result.get("currentVersionReleaseDate") or result.get("releaseDate")),
        )

    def lookup_google_play(self, identifier: str) -> StoreListing:
        try:
            response = self.session.get(
                "https://play.google.com/store/apps/details",
                params={
                    "id": identifier,
                    "hl": "en_US",
                    "gl": self.country,
                },
                timeout=self.timeout_seconds,
            )
            if response.status_code == 404:
                return StoreListing(platform=GOOGLE_PLATFORM, status="not_found_publicly", identifier=identifier)
            response.raise_for_status()
        except requests.exceptions.SSLError as exc:
            LOGGER.debug("Google Play TLS lookup failed for %s: %s", identifier, exc)
            return StoreListing(platform=GOOGLE_PLATFORM, status="tls_error", identifier=identifier, error=str(exc))
        except requests.RequestException as exc:
            LOGGER.debug("Google Play lookup failed for %s: %s", identifier, exc)
            return StoreListing(platform=GOOGLE_PLATFORM, status="error", identifier=identifier, error=str(exc))

        parser = MetaTagParser()
        parser.feed(response.text)
        raw_title = parser.meta.get("og:title") or parser.title
        name = normalize_google_play_title(raw_title)
        url = parser.meta.get("og:url") or response.url or google_play_url(identifier, self.country)

        if (
            not name
            or google_play_not_found_text(response.text)
            or not google_play_app_page(parser.meta, raw_title, identifier)
        ):
            return StoreListing(
                platform=GOOGLE_PLATFORM,
                status="not_found_publicly",
                identifier=identifier,
                url=google_play_url(identifier, self.country),
            )

        return StoreListing(
            platform=GOOGLE_PLATFORM,
            status="found",
            name=name,
            identifier=identifier,
            url=clean_value(url),
            version=extract_google_play_version(response.text),
            last_updated=extract_google_play_updated(response.text),
        )


class MetaTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "title":
            self._in_title = True
            return
        if tag != "meta":
            return
        values = {key: value for key, value in attrs if value is not None}
        key = values.get("property") or values.get("name")
        content = values.get("content")
        if key and content:
            self.meta[key] = clean_value(unescape(content))

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and not self.title:
            self.title = clean_value(unescape(data))


def target_store_platforms(categories: Iterable[str]) -> tuple[str, ...]:
    category_set = set(categories)
    platforms: list[str] = []

    if "ios" in category_set:
        platforms.append(APPLE_PLATFORM)
    if "android" in category_set or "android_library" in category_set:
        platforms.append(GOOGLE_PLATFORM)
    if not platforms and category_set.intersection(CROSS_PLATFORM_CATEGORIES):
        platforms.extend(BOTH_STORE_PLATFORMS)
    if not platforms:
        platforms.extend(BOTH_STORE_PLATFORMS)

    return tuple(dict.fromkeys(platforms))


def store_columns(
    identifier: str,
    categories: Iterable[str],
    store_client: StoreLookupClient | None,
) -> dict[str, str]:
    if store_client is None:
        return store_columns_from_listings(disabled_store_listings())

    cleaned_identifier = clean_value(identifier)
    if not cleaned_identifier:
        return store_columns_from_listings(identifier_missing_store_listings(categories))
    if not is_store_identifier_candidate(cleaned_identifier):
        return store_columns_from_listings(invalid_identifier_store_listings(categories, cleaned_identifier))

    return store_columns_from_listings(store_client.lookup(cleaned_identifier, categories))


def disabled_store_listings() -> list[StoreListing]:
    return [
        StoreListing(platform=APPLE_PLATFORM, status="disabled"),
        StoreListing(platform=GOOGLE_PLATFORM, status="disabled"),
    ]


def identifier_missing_store_listings(categories: Iterable[str]) -> list[StoreListing]:
    requested = set(target_store_platforms(categories))
    return [
        StoreListing(
            platform=APPLE_PLATFORM,
            status="identifier_missing" if APPLE_PLATFORM in requested else "not_requested",
        ),
        StoreListing(
            platform=GOOGLE_PLATFORM,
            status="identifier_missing" if GOOGLE_PLATFORM in requested else "not_requested",
        ),
    ]


def invalid_identifier_store_listings(categories: Iterable[str], identifier: str) -> list[StoreListing]:
    requested = set(target_store_platforms(categories))
    return [
        StoreListing(
            platform=APPLE_PLATFORM,
            status="identifier_invalid" if APPLE_PLATFORM in requested else "not_requested",
            identifier=identifier if APPLE_PLATFORM in requested else "",
        ),
        StoreListing(
            platform=GOOGLE_PLATFORM,
            status="identifier_invalid" if GOOGLE_PLATFORM in requested else "not_requested",
            identifier=identifier if GOOGLE_PLATFORM in requested else "",
        ),
    ]


def is_store_identifier_candidate(identifier: str) -> bool:
    cleaned_identifier = clean_value(identifier)
    return bool(
        cleaned_identifier
        and len(cleaned_identifier) <= 255
        and STORE_IDENTIFIER_PATTERN.match(cleaned_identifier)
    )


def store_columns_from_listings(listings: Iterable[StoreListing]) -> dict[str, str]:
    listing_by_platform = {listing.platform: listing for listing in listings}
    apple = listing_by_platform.get(APPLE_PLATFORM) or StoreListing(platform=APPLE_PLATFORM, status="not_requested")
    google = listing_by_platform.get(GOOGLE_PLATFORM) or StoreListing(platform=GOOGLE_PLATFORM, status="not_requested")
    found_platforms = [
        display_name_for_platform(listing.platform)
        for listing in (apple, google)
        if listing.status == "found"
    ]

    columns = {
        "store_lookup_status": aggregate_store_status((apple, google)),
        "store_validation_passed": store_validation_result((apple, google)),
        "store_platforms": "; ".join(found_platforms),
    }
    columns.update(listing_column_values(APPLE_PLATFORM, apple))
    columns.update(listing_column_values(GOOGLE_PLATFORM, google))
    return columns


def listing_column_values(platform: str, listing: StoreListing) -> dict[str, str]:
    return {
        f"{platform}_name": listing.name,
        f"{platform}_identifier": listing.identifier,
        f"{platform}_url": listing.url,
        f"{platform}_version": listing.version,
        f"{platform}_last_updated": listing.last_updated,
        f"{platform}_validation_passed": listing_validation_result(listing),
        f"{platform}_lookup_status": listing.status,
    }


def store_validation_result(listings: Iterable[StoreListing]) -> str:
    requested = [listing for listing in listings if listing.status != "not_requested"]
    return boolean_text(bool(requested) and all(listing.status == "found" for listing in requested))


def listing_validation_result(listing: StoreListing) -> str:
    return boolean_text(listing.status == "found")


def boolean_text(value: bool) -> str:
    return "TRUE" if value else "FALSE"


def aggregate_store_status(listings: Iterable[StoreListing]) -> str:
    statuses = [listing.status for listing in listings]
    requested = [status for status in statuses if status != "not_requested"]
    if not requested:
        return "not_requested"
    if all(status == "disabled" for status in requested):
        return "disabled"
    if all(status == "identifier_missing" for status in requested):
        return "identifier_missing"
    if all(status == "identifier_invalid" for status in requested):
        return "identifier_invalid"
    if any(status == "found" for status in requested):
        if all(status in {"found", "not_requested"} for status in statuses):
            return "found"
        return "partial_found"
    if any(status in {"error", "tls_error"} for status in requested):
        return "error"
    if all(status in {"not_found", "not_found_publicly"} for status in requested):
        return "not_found"
    return "not_found"


def display_name_for_platform(platform: str) -> str:
    if platform == APPLE_PLATFORM:
        return APPLE_DISPLAY_NAME
    if platform == GOOGLE_PLATFORM:
        return GOOGLE_DISPLAY_NAME
    return platform


def normalize_google_play_title(title: str) -> str:
    text = clean_value(title)
    suffixes = (" - Apps on Google Play", " - Google Play")
    for suffix in suffixes:
        if text.endswith(suffix):
            return clean_value(text[: -len(suffix)])
    return text


def google_play_not_found_text(text: str) -> bool:
    lowered = text.lower()
    return "requested url was not found" in lowered or ("we're sorry" in lowered and "not found" in lowered)


def google_play_app_page(meta: dict[str, str], title: str, identifier: str) -> bool:
    og_url = meta.get("og:url", "")
    return "Apps on Google Play" in title or (
        "/store/apps/details" in og_url and f"id={identifier}" in og_url
    )


def extract_google_play_version(text: str) -> str:
    return regex_store_value(text, r'"softwareVersion"\s*:\s*"([^"]+)"')


def extract_google_play_updated(text: str) -> str:
    return regex_store_value(text, r'"dateModified"\s*:\s*"([^"]+)"') or regex_store_value(
        text,
        r'"datePublished"\s*:\s*"([^"]+)"',
    )


def regex_store_value(text: str, pattern: str) -> str:
    match = re.search(pattern, text)
    if not match:
        return ""
    return clean_value(unescape(match.group(1)))


def google_play_url(identifier: str, country: str) -> str:
    return f"https://play.google.com/store/apps/details?id={identifier}&gl={clean_value(country).upper() or 'US'}"
