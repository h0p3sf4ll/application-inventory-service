API_VERSION = "7.1"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_WORKERS = 8
DEFAULT_BRANCH_WORKERS = 16
DEFAULT_CONTENT_WORKERS = 16
DEFAULT_COMMIT_PAGE_SIZE = 1000
DEFAULT_BRANCH_AGE_DAYS = 90
DEFAULT_STORE_COUNTRY = "US"
DEFAULT_STORE_TIMEOUT_SECONDS = 15
DEFAULT_ACTIVITY_MODE = "contributors"
DEFAULT_OUT_PREFIX = "appsec_inventory_service"
DEFAULT_POSTGRES_TABLE = "appsec_inventory_assets"
DEFAULT_POSTGRES_HOST = "localhost"
DEFAULT_POSTGRES_PORT = 5432
DEFAULT_POSTGRES_DATABASE = "postgres"
DEFAULT_POSTGRES_USER = "postgres"
DEFAULT_POSTGRES_PASSWORD = ""
MISSING_REQUESTS_MESSAGE = "Missing dependency: requests. Install it with `python -m pip install -r requirements.txt`."
MISSING_PSYCOPG_MESSAGE = "Missing dependency: psycopg. Install it with `python -m pip install 'psycopg[binary]>=3.2.0'`."
MISSING_CRYPTOGRAPHY_MESSAGE = "Missing dependency: cryptography. Install it with `python -m pip install 'cryptography>=42.0.0'`."

FALLBACK_BRANCH_PRIORITY = (
    ("production", 100),
    ("prod", 100),
    ("preproduction", 95),
    ("preprod", 95),
    ("pre-prod", 95),
    ("release", 90),
    ("staging", 85),
    ("stage", 85),
    ("main", 80),
    ("master", 78),
    ("development", 70),
    ("develop", 70),
    ("dev", 65),
)


def active_sheet_name(branch_age_days: int = DEFAULT_BRANCH_AGE_DAYS) -> str:
    return f"Active {branch_age_days}d"


def older_sheet_name(branch_age_days: int = DEFAULT_BRANCH_AGE_DAYS) -> str:
    return f"Older {branch_age_days}d"


ACTIVE_SHEET_NAME = active_sheet_name()
OLDER_SHEET_NAME = older_sheet_name()

KNOWN_CATEGORIES = (
    "android",
    "ios",
    "flutter",
    "react_native",
    "ionic_capacitor_cordova",
    "xamarin_maui",
    "pipeline_mobile",
    "android_library",
    "web_frontend",
    "web_backend",
    "api_service",
    "microservice",
    "middleware",
    "serverless",
    "containerized_service",
    "infrastructure_as_code",
    "ai_enabled",
    "llm_integration",
    "ai_orchestration",
    "ml_inference",
    "vector_search",
    "ai_service_integration",
)

CATEGORY_FIELDNAMES = tuple(f"category_{category}" for category in KNOWN_CATEGORIES)

KNOWN_INVENTORY_TYPES = (
    "mobile_app",
    "web_app",
    "api_service",
    "microservice",
    "middleware",
    "serverless",
    "library",
    "infrastructure",
    "ai_enabled",
)

TYPE_FIELDNAMES = tuple(f"type_{inventory_type}" for inventory_type in KNOWN_INVENTORY_TYPES)

APPLICATION_TYPE_LABELS = {
    "mobile_app": "Mobile app",
    "web_app": "Web app",
    "api_service": "API service",
    "microservice": "Microservice",
    "middleware": "Middleware",
    "serverless": "Serverless",
    "library": "Library",
    "infrastructure": "Infrastructure",
    "ai_enabled": "AI-enabled",
}

STORE_FIELDNAMES = (
    "store_lookup_status",
    "store_validation_passed",
    "store_platforms",
    "apple_app_store_name",
    "apple_app_store_identifier",
    "apple_app_store_url",
    "apple_app_store_version",
    "apple_app_store_last_updated",
    "apple_app_store_validation_passed",
    "apple_app_store_lookup_status",
    "google_play_name",
    "google_play_identifier",
    "google_play_url",
    "google_play_version",
    "google_play_last_updated",
    "google_play_validation_passed",
    "google_play_lookup_status",
)

CONTENT_FILES_TO_FETCH: tuple[str, ...] = (
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "app.json",
    "expo.json",
    "app.config.js",
    "app.config.ts",
    "pubspec.yaml",
    "pyproject.toml",
    "requirements.txt",
    "Pipfile",
    "poetry.lock",
    "requirements.in",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "setup.cfg",
    "setup.py",
    "environment.yml",
    "environment.yaml",
    "pom.xml",
    "go.mod",
    "Cargo.toml",
    "composer.json",
    "Gemfile",
    "AndroidManifest.xml",
    "Info.plist",
    "InfoPlist.strings",
    "project.pbxproj",
    ".xcconfig",
    "strings.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.properties",
    "azure-pipelines.yml",
    "azure-pipeline.yml",
    ".csproj",
    ".props",
    "Podfile",
    "capacitor.config.ts",
    "capacitor.config.json",
    "ionic.config.json",
    "config.xml",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "Chart.yaml",
    "values.yaml",
    "kustomization.yaml",
    "serverless.yml",
    "serverless.yaml",
    "application.yml",
    "application.yaml",
    "application.properties",
    "main.tf",
)

CONTENT_FILE_SUFFIXES = tuple(name.lower() for name in CONTENT_FILES_TO_FETCH)

CSV_FIELDNAMES = (
    "project",
    "repo_name",
    "branch_name",
    "branch_last_updated",
    "branch_age_bucket",
    "web_url",
    "source_url",
    "inventory_name",
    "inventory_version",
    "inventory_types",
    "primary_language",
    "scanner_target",
    "semgrep_target",
    "sonarqube_project_key",
    "sonarqube_project_name",
    "mobile_name",
    "mobile_version",
    "mobile_identifier",
    "mobile_identifier_source",
    "mobile_identifier_status",
    "contributing_developers",
    "last_updated",
    "confidence",
    "score",
    "categories",
    *TYPE_FIELDNAMES,
    *CATEGORY_FIELDNAMES,
    *STORE_FIELDNAMES,
    "detection_evidence",
)

SCANNER_TARGET_FIELDNAMES = (
    "project",
    "repo_name",
    "branch_name",
    "branch_last_updated",
    "source_url",
    "web_url",
    "inventory_name",
    "inventory_version",
    "inventory_types",
    "primary_language",
    "categories",
    "confidence",
    "score",
    "semgrep_target",
    "sonarqube_project_key",
    "sonarqube_project_name",
)

SONARQUBE_FIELDNAMES = (
    "sonar.projectKey",
    "sonar.projectName",
    "sonar.sources",
    "branch",
    "source_url",
    "web_url",
    "project",
    "repo_name",
    "inventory_types",
    "categories",
)
