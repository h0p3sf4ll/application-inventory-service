from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from .metadata import (
    collect_metadata_properties,
    parse_android_manifest,
    parse_capacitor_json,
    parse_capacitor_ts,
    parse_cordova_config,
    parse_csproj,
    parse_expo_config,
    parse_gradle_metadata,
    parse_info_plist,
    parse_info_plist_strings,
    parse_xcode_settings_metadata,
)
from .models import DetectionEvidence
from .utils import (
    load_json_object,
    merged_package_dependencies,
    normalize_path,
    regex_value,
    xml_text,
    yaml_has_flutter_dependency,
)

AI_LLM_DEPENDENCIES = frozenset(
    {
        "@ai-sdk/anthropic",
        "@ai-sdk/azure",
        "@ai-sdk/cohere",
        "@ai-sdk/google",
        "@ai-sdk/mistral",
        "@ai-sdk/openai",
        "@anthropic-ai/sdk",
        "@aws-sdk/client-bedrock-runtime",
        "@azure/ai-inference",
        "@azure/ai-openai",
        "@azure/ai-projects",
        "@azure/openai",
        "@google/generative-ai",
        "@google/genai",
        "@google-cloud/vertexai",
        "@huggingface/inference",
        "@mistralai/mistralai",
        "anthropic",
        "azure-ai-inference",
        "azure-ai-openai",
        "azure-ai-projects",
        "azure.ai.inference",
        "azure.ai.openai",
        "awssdk.bedrockruntime",
        "bedrockruntime",
        "cloud.google.com/go/vertexai/genai",
        "cohere",
        "cohere-ai",
        "cohere-ai/cohere-go",
        "dev.langchain4j",
        "github.com/aws/aws-sdk-go-v2/service/bedrockruntime",
        "github.com/cohere-ai/cohere-go",
        "github.com/google/generative-ai-go",
        "github.com/ollama/ollama/api",
        "github.com/sashabaranov/go-openai",
        "github.com/tmc/langchaingo",
        "google-ai-generativelanguage",
        "google-cloud-vertexai",
        "google.ai.generativelanguage",
        "google-genai",
        "google-generativeai",
        "google.cloud.vertexai",
        "groq",
        "groq-sdk",
        "langchain4j-open-ai",
        "langchain4j-open-ai-spring-boot-starter",
        "mistralai",
        "mistralai/mistralai",
        "microsoft.semantickernel.connectors.azureopenai",
        "microsoft.semantickernel.connectors.openai",
        "ollama",
        "ollamasharp",
        "openai",
        "openai-java",
        "replicate",
        "software.amazon.awssdk:bedrockruntime",
        "spring-ai-anthropic-spring-boot-starter",
        "spring-ai-azure-openai-spring-boot-starter",
        "spring-ai-bedrock",
        "spring-ai-bedrock-ai-spring-boot-starter",
        "spring-ai-openai",
        "spring-ai-openai-spring-boot-starter",
        "spring-ai-starter-model-anthropic",
        "spring-ai-starter-model-azure-openai",
        "spring-ai-starter-model-bedrock",
        "spring-ai-starter-model-openai",
    }
)

AI_ORCHESTRATION_DEPENDENCIES = frozenset(
    {
        "@langchain/anthropic",
        "@langchain/community",
        "@langchain/core",
        "@langchain/google-genai",
        "@langchain/openai",
        "autogen-core",
        "autogen-agentchat",
        "crewai",
        "dev.langchain4j",
        "haystack-ai",
        "langchain",
        "langchain-core",
        "langchain-openai",
        "langchain4j",
        "llama-index",
        "llamaindex",
        "microsoft.semantickernel.agents.core",
        "microsoft.semantickernel",
        "pyautogen",
        "semantic-kernel",
        "spring-ai",
    }
)

AI_ML_INFERENCE_DEPENDENCIES = frozenset(
    {
        "@tensorflow/tfjs",
        "@xenova/transformers",
        "deeplearning4j",
        "diffusers",
        "keras",
        "lightgbm",
        "microsoft.ml",
        "microsoft.ml.onnxruntime",
        "microsoft.ml.onnxruntimegenai",
        "ml5",
        "mlflow",
        "onnxruntime",
        "onnxruntime-node",
        "onnxruntime-web",
        "org.deeplearning4j",
        "org.tensorflow",
        "pytorch",
        "scikit-learn",
        "sentence-transformers",
        "tensorflow",
        "tensorflow-macos",
        "tensorflow.net",
        "torch",
        "transformers",
        "transformers.js",
        "tribuo",
        "weka",
        "xgboost",
    }
)

AI_VECTOR_SEARCH_DEPENDENCIES = frozenset(
    {
        "@pinecone-database/pinecone",
        "@qdrant/js-client-rest",
        "chromadb",
        "dev.langchain4j:langchain4j-pinecone",
        "faiss-cpu",
        "faiss-gpu",
        "faiss-node",
        "github.com/pinecone-io/go-pinecone",
        "github.com/qdrant/go-client",
        "github.com/weaviate/weaviate-go-client",
        "io.pinecone",
        "lancedb",
        "pgvector",
        "pinecone",
        "pinecone-client",
        "qdrant-client",
        "qdrant.client",
        "redisvl",
        "spring-ai-pinecone-store-spring-boot-starter",
        "spring-ai-starter-vector-store-chroma",
        "spring-ai-starter-vector-store-pgvector",
        "spring-ai-starter-vector-store-pinecone",
        "spring-ai-starter-vector-store-qdrant",
        "spring-ai-starter-vector-store-redis",
        "spring-ai-starter-vector-store-weaviate",
        "weaviate-client",
        "weaviate-ts-client",
    }
)

AI_SERVICE_DEPENDENCIES = frozenset(
    {
        "@aws-sdk/client-comprehend",
        "@aws-sdk/client-rekognition",
        "@aws-sdk/client-sagemaker-runtime",
        "@aws-sdk/client-textract",
        "@azure/ai-document-intelligence",
        "@azure/ai-form-recognizer",
        "@azure/ai-language-text",
        "@azure/ai-text-analytics",
        "@azure/ai-vision-image-analysis",
        "@azure/cognitiveservices-computervision",
        "@google-cloud/aiplatform",
        "@google-cloud/documentai",
        "@google-cloud/language",
        "@google-cloud/speech",
        "@google-cloud/translate",
        "@google-cloud/vision",
        "amazon-textract-textractor",
        "awssdk.comprehend",
        "awssdk.rekognition",
        "awssdk.sagemakerruntime",
        "awssdk.textract",
        "comprehend",
        "azure-ai-documentintelligence",
        "azure-ai-formrecognizer",
        "azure-ai-textanalytics",
        "azure-ai-vision-imageanalysis",
        "azure.ai.documentintelligence",
        "azure.ai.formrecognizer",
        "azure.ai.language.conversations",
        "azure.ai.textanalytics",
        "azure.ai.vision.imageanalysis",
        "azure-cognitiveservices-vision-computervision",
        "cloud.google.com/go/ai",
        "cloud.google.com/go/documentai",
        "cloud.google.com/go/speech",
        "cloud.google.com/go/translate",
        "cloud.google.com/go/vision",
        "documentai",
        "google-cloud-aiplatform",
        "google-cloud-documentai",
        "google-cloud-language",
        "google-cloud-speech",
        "google-cloud-translate",
        "google-cloud-vision",
        "google.cloud.documentai",
        "google.cloud.speech",
        "google.cloud.translate",
        "google.cloud.vision",
        "huggingface-hub",
        "huggingface_hub",
        "rekognition",
        "sagemakerruntime",
        "software.amazon.awssdk:comprehend",
        "software.amazon.awssdk:rekognition",
        "software.amazon.awssdk:sagemakerruntime",
        "software.amazon.awssdk:textract",
        "textract",
    }
)

AI_DEPENDENCY_RULES = (
    ("llm_integration", "LLM or generative AI dependency", AI_LLM_DEPENDENCIES, 4),
    ("ai_orchestration", "AI orchestration or agent framework dependency", AI_ORCHESTRATION_DEPENDENCIES, 4),
    ("ml_inference", "ML inference dependency", AI_ML_INFERENCE_DEPENDENCIES, 3),
    ("vector_search", "Vector search dependency", AI_VECTOR_SEARCH_DEPENDENCIES, 3),
    ("ai_service_integration", "Cloud AI service dependency", AI_SERVICE_DEPENDENCIES, 3),
)

AI_LLM_CONFIG_PATTERNS = (
    r"(?ms)^\s*spring\s*:\s.*?^\s+ai\s*:",
    r"\bspring\.ai\.",
    r"\bazure\.openai\b",
    r"(?m)^\s*openai\s*:",
    r"\bopenai\.(?:api|endpoint|model|deployment)",
    r"(?m)^\s*anthropic\s*:",
    r"\banthropic\.(?:api|model)",
    r"\bbedrock(?:runtime)?\b",
    r"\bllm\.(?:provider|model|endpoint)",
)

AI_VECTOR_CONFIG_PATTERNS = (
    r"\bvectorstore\b",
    r"\bvector-store\b",
    r"\bpgvector\b",
    r"\bchromadb\b",
    r"\bqdrant\b",
    r"\bpinecone\b",
    r"\bweaviate\b",
)

AI_ML_CONFIG_PATTERNS = (
    r"\bmlflow\.",
    r"\bmlflow\s*:",
    r"\bonnxruntime\b",
    r"\btensorflow(?:_serving|[.-]serving)?\b",
    r"\btorchserve\b",
    r"\bsagemaker(?:runtime)?\b",
    r"\bmodel_uri\b",
    r"\bmodel_path\b",
)

AI_CONTAINER_RUNTIME_TOKENS = (
    "ghcr.io/huggingface/text-generation-inference",
    "ollama/ollama",
    "pytorch/torchserve",
    "tensorflow/serving",
    "vllm/vllm-openai",
)


def detect_mobile_repo(
    paths: Iterable[str],
    file_contents: dict[str, str],
) -> tuple[str, list[DetectionEvidence], int]:
    evidence = collect_detection_evidence(paths, file_contents)
    score = sum(item.weight for item in evidence)
    has_strong_app_evidence = any(item.weight >= 3 for item in evidence)
    has_structural_app_evidence = any(item.category != "pipeline_mobile" for item in evidence)

    if score >= 7 and has_strong_app_evidence:
        confidence = "high"
    elif score >= 4 and has_structural_app_evidence:
        confidence = "medium"
    elif score >= 2 and has_structural_app_evidence:
        confidence = "low"
    else:
        confidence = "none"

    return confidence, evidence, score


def detect_inventory_repo(
    paths: Iterable[str],
    file_contents: dict[str, str],
) -> tuple[str, list[DetectionEvidence], int]:
    evidence = collect_inventory_evidence(paths, file_contents)
    score = sum(item.weight for item in evidence)
    has_strong_evidence = any(item.weight >= 3 for item in evidence)
    has_structural_evidence = any(
        item.category not in {"pipeline_mobile", "containerized_service", "infrastructure_as_code"}
        for item in evidence
    )

    if score >= 8 and has_strong_evidence and has_structural_evidence:
        confidence = "high"
    elif score >= 3 and has_strong_evidence and has_structural_evidence:
        confidence = "medium"
    elif score >= 2 and has_structural_evidence:
        confidence = "low"
    else:
        confidence = "none"

    return confidence, evidence, score


def collect_detection_evidence(
    paths: Iterable[str],
    file_contents: dict[str, str],
) -> list[DetectionEvidence]:
    evidence: list[DetectionEvidence] = []
    path_set = {normalize_path(path).lower() for path in paths}
    properties = collect_metadata_properties(file_contents)
    evidence.extend(collect_path_evidence(path_set))

    for path, content in file_contents.items():
        lower_path = normalize_path(path).lower()
        if lower_path.endswith("androidmanifest.xml"):
            evidence.extend(detect_android_manifest_evidence(path, content))
        elif lower_path.endswith("build.gradle") or lower_path.endswith("build.gradle.kts"):
            evidence.extend(detect_gradle_evidence(path, content, properties))
        elif lower_path.endswith("info.plist"):
            evidence.extend(detect_info_plist_evidence(path, content, properties))
        elif lower_path.endswith("infoplist.strings"):
            evidence.extend(detect_info_plist_strings_evidence(path, content))
        elif lower_path.endswith("project.pbxproj") or lower_path.endswith(".xcconfig"):
            evidence.extend(detect_xcode_settings_evidence(path, content))
        elif lower_path.endswith("pubspec.yaml"):
            evidence.extend(detect_pubspec_evidence(path, content, path_set))
        elif lower_path.endswith("package.json"):
            evidence.extend(detect_package_json_evidence(path, content))
        elif lower_path.endswith("app.json") or lower_path.endswith("expo.json"):
            evidence.extend(detect_expo_evidence(path, content))
        elif lower_path.endswith("app.config.js") or lower_path.endswith("app.config.ts"):
            evidence.extend(detect_expo_dynamic_config_evidence(path, content))
        elif lower_path.endswith("capacitor.config.json"):
            evidence.extend(detect_capacitor_json_evidence(path, content))
        elif lower_path.endswith("capacitor.config.ts"):
            evidence.extend(detect_capacitor_ts_evidence(path, content))
        elif lower_path.endswith("config.xml"):
            evidence.extend(detect_cordova_evidence(path, content))
        elif lower_path.endswith(".csproj"):
            evidence.extend(detect_csproj_evidence(path, content))
        elif lower_path.endswith("azure-pipelines.yml") or lower_path.endswith("azure-pipeline.yml"):
            evidence.extend(detect_pipeline_evidence(path, content))

    return dedupe_evidence(evidence)


def collect_inventory_evidence(
    paths: Iterable[str],
    file_contents: dict[str, str],
) -> list[DetectionEvidence]:
    evidence = collect_detection_evidence(paths, file_contents)
    path_set = {normalize_path(path).lower() for path in paths}
    evidence.extend(collect_inventory_path_evidence(path_set))

    for path, content in file_contents.items():
        lower_path = normalize_path(path).lower()
        if lower_path.endswith("package.json"):
            evidence.extend(detect_package_json_inventory_evidence(path, content))
        elif lower_path.endswith("build.gradle") or lower_path.endswith("build.gradle.kts"):
            evidence.extend(detect_gradle_inventory_evidence(path, content))
        elif lower_path.endswith("pom.xml"):
            evidence.extend(detect_pom_inventory_evidence(path, content))
        elif (
            lower_path.endswith("requirements.txt")
            or lower_path.endswith("requirements.in")
            or lower_path.endswith("requirements-dev.txt")
            or lower_path.endswith("requirements-prod.txt")
            or lower_path.endswith("pyproject.toml")
            or lower_path.endswith("pipfile")
            or lower_path.endswith("setup.cfg")
            or lower_path.endswith("setup.py")
            or lower_path.endswith("environment.yml")
            or lower_path.endswith("environment.yaml")
        ):
            evidence.extend(detect_python_inventory_evidence(path, content))
        elif lower_path.endswith("go.mod"):
            evidence.extend(detect_go_mod_inventory_evidence(path, content))
        elif lower_path.endswith(".csproj"):
            evidence.extend(detect_csproj_inventory_evidence(path, content))
        elif lower_path.endswith("dockerfile") or "docker-compose" in lower_path or lower_path.endswith("/compose.yml") or lower_path.endswith("/compose.yaml"):
            evidence.extend(detect_container_evidence(path, content))
        elif lower_path.endswith("serverless.yml") or lower_path.endswith("serverless.yaml"):
            evidence.extend(detect_serverless_evidence(path, content))
        elif (
            lower_path.endswith("chart.yaml")
            or lower_path.endswith("kustomization.yaml")
            or lower_path.endswith("main.tf")
            or lower_path.endswith("values.yaml")
        ):
            evidence.extend(detect_infrastructure_evidence(path, content))
        elif (
            lower_path.endswith("application.yml")
            or lower_path.endswith("application.yaml")
            or lower_path.endswith("application.properties")
        ):
            evidence.extend(detect_application_config_evidence(path, content))

    return dedupe_evidence(evidence)


def collect_path_evidence(path_set: set[str]) -> list[DetectionEvidence]:
    evidence: list[DetectionEvidence] = []
    has_android_dir = any(path.startswith("/android/") or "/android/" in path for path in path_set)
    has_ios_dir = any(path.startswith("/ios/") or "/ios/" in path for path in path_set)
    has_pubspec = any(path.endswith("/pubspec.yaml") for path in path_set)

    if any(path.endswith(".xcodeproj") or path.endswith(".xcworkspace") for path in path_set):
        evidence.append(
            DetectionEvidence("ios", "xcode_project", "Xcode project/workspace file present", 2)
        )
    if any(path.endswith("/androidmanifest.xml") for path in path_set):
        evidence.append(
            DetectionEvidence("android", "android_manifest_path", "Android manifest file present", 1)
        )
    if has_pubspec and has_android_dir and has_ios_dir:
        evidence.append(
            DetectionEvidence(
                "flutter",
                "flutter_project_layout",
                "pubspec.yaml plus android and ios project folders",
                2,
            )
        )
    return evidence


def collect_inventory_path_evidence(path_set: set[str]) -> list[DetectionEvidence]:
    evidence: list[DetectionEvidence] = []
    if any(path.endswith("/dockerfile") or "/dockerfile" in path for path in path_set):
        evidence.append(DetectionEvidence("containerized_service", "dockerfile_path", "Dockerfile present", 1))
    if any("docker-compose" in path or path.endswith("/compose.yml") or path.endswith("/compose.yaml") for path in path_set):
        evidence.append(DetectionEvidence("containerized_service", "compose_path", "Compose file present", 1))
    if any(path.endswith("/serverless.yml") or path.endswith("/serverless.yaml") for path in path_set):
        evidence.append(DetectionEvidence("serverless", "serverless_path", "Serverless configuration present", 2))
    if any(
        path.endswith("/chart.yaml") or path.endswith("/kustomization.yaml") or path.endswith("/main.tf")
        for path in path_set
    ):
        evidence.append(
            DetectionEvidence("infrastructure_as_code", "deployment_config_path", "Deployment configuration present", 1)
        )
    if any(
        path.endswith("/index.html")
        or path.endswith("/src/app.ts")
        or path.endswith("/src/app.tsx")
        or path.endswith("/src/main.ts")
        or path.endswith("/src/main.tsx")
        or path.endswith("/src/app.jsx")
        for path in path_set
    ):
        evidence.append(DetectionEvidence("web_frontend", "web_source_layout", "Frontend source layout present", 1))
    return evidence


def detect_android_manifest_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_android_manifest(content)
    if metadata.identifier:
        return [DetectionEvidence("android", path, f"Android package {metadata.identifier}", 4)]
    if metadata.version or metadata.name:
        return [DetectionEvidence("android", path, "Parsed Android application manifest", 2)]
    return []


def detect_gradle_evidence(
    path: str,
    content: str,
    properties: dict[str, str] | None = None,
) -> list[DetectionEvidence]:
    metadata = parse_gradle_metadata(content, properties or {})
    evidence: list[DetectionEvidence] = []
    if re.search(r"\bcom\.android\.application\b", content):
        evidence.append(DetectionEvidence("android", path, "Gradle Android application plugin", 4))
    elif re.search(r"\bcom\.android\.library\b", content):
        evidence.append(DetectionEvidence("android_library", path, "Gradle Android library plugin", 1))
    if metadata.identifier:
        evidence.append(DetectionEvidence("android", path, f"Gradle applicationId {metadata.identifier}", 3))
    return evidence


def detect_info_plist_evidence(
    path: str,
    content: str,
    properties: dict[str, str] | None = None,
) -> list[DetectionEvidence]:
    metadata = parse_info_plist(content, properties or {})
    if metadata.identifier:
        return [DetectionEvidence("ios", path, f"CFBundleIdentifier {metadata.identifier}", 4)]
    if metadata.name or metadata.version:
        return [DetectionEvidence("ios", path, "Parsed iOS Info.plist app metadata", 2)]
    return []


def detect_info_plist_strings_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_info_plist_strings(content)
    if metadata.name:
        return [DetectionEvidence("ios", path, "Localized iOS display name", 1)]
    return []


def detect_xcode_settings_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_xcode_settings_metadata(content)
    if metadata.identifier:
        return [DetectionEvidence("ios", path, f"PRODUCT_BUNDLE_IDENTIFIER {metadata.identifier}", 4)]
    if metadata.version:
        return [DetectionEvidence("ios", path, "Xcode marketing version configured", 1)]
    return []


def detect_pubspec_evidence(path: str, content: str, path_set: set[str]) -> list[DetectionEvidence]:
    evidence: list[DetectionEvidence] = []
    has_android_dir = any(candidate.startswith("/android/") or "/android/" in candidate for candidate in path_set)
    has_ios_dir = any(candidate.startswith("/ios/") or "/ios/" in candidate for candidate in path_set)
    if yaml_has_flutter_dependency(content):
        evidence.append(DetectionEvidence("flutter", path, "pubspec.yaml declares Flutter SDK dependency", 4))
    if has_android_dir and has_ios_dir:
        evidence.append(DetectionEvidence("flutter", path, "Flutter-style android and ios folders present", 1))
    return evidence


def detect_package_json_evidence(path: str, content: str) -> list[DetectionEvidence]:
    dependencies = merged_package_dependencies(load_json_object(content))
    evidence: list[DetectionEvidence] = []

    if "react-native" in dependencies:
        evidence.append(DetectionEvidence("react_native", path, "package.json dependency react-native", 4))
    if "expo" in dependencies:
        evidence.append(DetectionEvidence("react_native", path, "package.json dependency expo", 3))
    if "@capacitor/core" in dependencies:
        evidence.append(
            DetectionEvidence("ionic_capacitor_cordova", path, "package.json dependency @capacitor/core", 4)
        )
    if "@ionic/angular" in dependencies or "@ionic/react" in dependencies or "@ionic/vue" in dependencies:
        evidence.append(
            DetectionEvidence("ionic_capacitor_cordova", path, "package.json Ionic framework dependency", 3)
        )
    if "cordova" in dependencies or "cordova-android" in dependencies or "cordova-ios" in dependencies:
        evidence.append(DetectionEvidence("ionic_capacitor_cordova", path, "package.json Cordova dependency", 3))
    return evidence


def detect_package_json_inventory_evidence(path: str, content: str) -> list[DetectionEvidence]:
    data = load_json_object(content)
    dependencies = merged_package_dependencies(data)
    evidence: list[DetectionEvidence] = []

    if dependencies & {
        "@angular/core",
        "@remix-run/react",
        "@sveltejs/kit",
        "next",
        "nuxt",
        "react",
        "svelte",
        "vite",
        "vue",
    }:
        evidence.append(DetectionEvidence("web_frontend", path, "package.json frontend framework dependency", 4))
    if dependencies & {
        "@apollo/server",
        "@fastify/autoload",
        "@nestjs/core",
        "@trpc/server",
        "apollo-server",
        "express",
        "fastify",
        "graphql-yoga",
        "hapi",
        "koa",
    }:
        evidence.append(DetectionEvidence("web_backend", path, "package.json backend framework dependency", 4))
        evidence.append(DetectionEvidence("api_service", path, "package.json API framework dependency", 3))
    if dependencies & {"@grpc/grpc-js", "grpc", "moleculer", "seneca"}:
        evidence.append(DetectionEvidence("microservice", path, "package.json service framework dependency", 3))
        evidence.append(DetectionEvidence("api_service", path, "package.json service API dependency", 2))
    if dependencies & {
        "@azure/service-bus",
        "amqplib",
        "bull",
        "bullmq",
        "ioredis",
        "kafkajs",
        "node-rdkafka",
        "redis",
    }:
        evidence.append(DetectionEvidence("middleware", path, "package.json messaging or queue dependency", 3))
    if dependencies & {"@azure/functions", "@netlify/functions", "@vercel/node", "aws-lambda", "serverless"}:
        evidence.append(DetectionEvidence("serverless", path, "package.json serverless dependency", 3))
    evidence.extend(detect_ai_dependency_name_evidence(path, dependencies, "package.json"))
    if has_script(data, ("start", "serve")) and evidence:
        evidence.append(DetectionEvidence("microservice", path, "package.json runtime script", 1))
    return evidence


def detect_gradle_inventory_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if any(token in lowered for token in ("org.springframework.boot", "spring-boot", "io.quarkus", "micronaut", "ktor")):
        evidence.append(DetectionEvidence("microservice", path, "Gradle service framework plugin or dependency", 4))
    if any(token in lowered for token in ("spring-boot-starter-web", "spring-boot-starter-webflux", "jaxrs", "grpc")):
        evidence.append(DetectionEvidence("api_service", path, "Gradle API framework dependency", 3))
        evidence.append(DetectionEvidence("web_backend", path, "Gradle web backend dependency", 3))
    if any(token in lowered for token in ("spring-kafka", "kafka-clients", "rabbitmq", "amqp", "camel-", "activemq")):
        evidence.append(DetectionEvidence("middleware", path, "Gradle messaging or integration dependency", 3))
    evidence.extend(detect_ai_dependency_text_evidence(path, lowered, "Gradle"))
    return evidence


def detect_pom_inventory_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if any(token in lowered for token in ("spring-boot", "quarkus", "micronaut", "helidon", "ktor")):
        evidence.append(DetectionEvidence("microservice", path, "Maven service framework dependency", 4))
    if any(token in lowered for token in ("spring-boot-starter-web", "spring-boot-starter-webflux", "jakarta.ws.rs", "javax.ws.rs", "grpc")):
        evidence.append(DetectionEvidence("api_service", path, "Maven API framework dependency", 3))
        evidence.append(DetectionEvidence("web_backend", path, "Maven web backend dependency", 3))
    if any(token in lowered for token in ("spring-kafka", "kafka-clients", "rabbitmq", "amqp", "camel-", "activemq")):
        evidence.append(DetectionEvidence("middleware", path, "Maven messaging or integration dependency", 3))
    evidence.extend(detect_ai_dependency_text_evidence(path, lowered, "Maven"))
    return evidence


def detect_python_inventory_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if dependency_text_has_any(lowered, ("django", "fastapi", "flask", "starlette", "tornado")):
        evidence.append(DetectionEvidence("web_backend", path, "Python web framework dependency", 4))
        evidence.append(DetectionEvidence("api_service", path, "Python API framework dependency", 3))
    if dependency_text_has_any(lowered, ("grpcio", "nameko", "pyro5")):
        evidence.append(DetectionEvidence("microservice", path, "Python service framework dependency", 3))
        evidence.append(DetectionEvidence("api_service", path, "Python service API dependency", 2))
    if dependency_text_has_any(lowered, ("celery", "confluent-kafka", "dramatiq", "kafka-python", "pika", "rq")):
        evidence.append(DetectionEvidence("middleware", path, "Python messaging or worker dependency", 3))
    if dependency_text_has_any(lowered, ("azure-functions", "functions-framework")):
        evidence.append(DetectionEvidence("serverless", path, "Python serverless dependency", 3))
    evidence.extend(detect_ai_dependency_text_evidence(path, lowered, "Python"))
    return evidence


def detect_go_mod_inventory_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if any(token in lowered for token in ("gin-gonic/gin", "go-chi/chi", "gofiber/fiber", "gorilla/mux", "labstack/echo")):
        evidence.append(DetectionEvidence("web_backend", path, "Go web framework dependency", 4))
        evidence.append(DetectionEvidence("api_service", path, "Go API framework dependency", 3))
    if any(token in lowered for token in ("google.golang.org/grpc", "go-micro.dev", "micro.dev")):
        evidence.append(DetectionEvidence("microservice", path, "Go service framework dependency", 3))
        evidence.append(DetectionEvidence("api_service", path, "Go service API dependency", 2))
    if any(token in lowered for token in ("shopify/sarama", "confluent-kafka-go", "streadway/amqp", "rabbitmq/amqp")):
        evidence.append(DetectionEvidence("middleware", path, "Go messaging dependency", 3))
    evidence.extend(detect_ai_dependency_text_evidence(path, lowered, "Go"))
    return evidence


def detect_csproj_inventory_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if "microsoft.net.sdk.web" in lowered or "microsoft.aspnetcore" in lowered:
        evidence.append(DetectionEvidence("web_backend", path, ".NET web SDK or ASP.NET dependency", 4))
        evidence.append(DetectionEvidence("api_service", path, ".NET API-capable project", 3))
    if "microsoft.net.sdk.worker" in lowered or "backgroundservice" in lowered or "ihostedservice" in lowered:
        evidence.append(DetectionEvidence("microservice", path, ".NET worker service project", 3))
        evidence.append(DetectionEvidence("middleware", path, ".NET background worker project", 2))
    if "grpc" in lowered:
        evidence.append(DetectionEvidence("api_service", path, ".NET gRPC dependency", 3))
        evidence.append(DetectionEvidence("microservice", path, ".NET gRPC service dependency", 2))
    evidence.extend(detect_ai_dependency_text_evidence(path, lowered, ".NET"))
    return evidence


def detect_container_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if any(token in lowered for token in (" from ", "from ", "services:", "image:", "build:", "expose ", "cmd ", "entrypoint ")):
        evidence.append(DetectionEvidence("containerized_service", path, "Container runtime configuration", 2))
    if any(token in lowered for token in AI_CONTAINER_RUNTIME_TOKENS):
        evidence.extend(ai_capability_evidence(path, "ml_inference", "Container AI runtime image", 3))
    return evidence


def detect_serverless_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    if "functions:" in lowered or "provider:" in lowered or "handler:" in lowered:
        return [DetectionEvidence("serverless", path, "Serverless functions configuration", 4)]
    return []


def detect_infrastructure_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    if any(token in lowered for token in ("apiversion:", "kind:", "resources:", "provider ", "resource ", "module ")):
        return [DetectionEvidence("infrastructure_as_code", path, "Infrastructure or deployment manifest", 1)]
    return []


def detect_application_config_evidence(path: str, content: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    evidence: list[DetectionEvidence] = []
    if "spring.application.name" in lowered or "server.port" in lowered:
        evidence.append(DetectionEvidence("microservice", path, "Spring application runtime configuration", 1))
    if "management.endpoints.web" in lowered:
        evidence.append(DetectionEvidence("web_backend", path, "Spring web management endpoints configured", 1))
    if any(re.search(pattern, lowered) for pattern in AI_LLM_CONFIG_PATTERNS):
        evidence.extend(ai_capability_evidence(path, "llm_integration", "AI or LLM runtime configuration", 3))
    if any(re.search(pattern, lowered) for pattern in AI_VECTOR_CONFIG_PATTERNS):
        evidence.extend(ai_capability_evidence(path, "vector_search", "Vector search runtime configuration", 2))
    if any(re.search(pattern, lowered) for pattern in AI_ML_CONFIG_PATTERNS):
        evidence.extend(ai_capability_evidence(path, "ml_inference", "ML model runtime configuration", 3))
    return evidence


def has_script(data: dict[str, object], names: Iterable[str]) -> bool:
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return False
    return any(name in scripts and str(scripts.get(name) or "").strip() for name in names)


def dependency_text_has_any(content: str, names: Iterable[str]) -> bool:
    return bool(dependency_text_matches(content, names))


def dependency_text_matches(content: str, names: Iterable[str]) -> list[str]:
    return sorted(
        {
            name
            for name in names
            if re.search(rf"(?<![a-z0-9_.-]){re.escape(name)}(?![a-z0-9_.-])", content)
        }
    )


def detect_ai_dependency_name_evidence(
    path: str,
    dependency_names: Iterable[str],
    source_label: str,
) -> list[DetectionEvidence]:
    normalized = {name.lower() for name in dependency_names}
    return collect_ai_dependency_evidence(
        path,
        source_label,
        lambda names: sorted(normalized & names),
    )


def detect_ai_dependency_text_evidence(path: str, content: str, source_label: str) -> list[DetectionEvidence]:
    lowered = content.lower()
    return collect_ai_dependency_evidence(
        path,
        source_label,
        lambda names: dependency_text_matches(lowered, names),
    )


def collect_ai_dependency_evidence(
    path: str,
    source_label: str,
    matcher: Callable[[frozenset[str]], list[str]],
) -> list[DetectionEvidence]:
    evidence: list[DetectionEvidence] = []
    matched_dependencies: list[str] = []
    matched_ml_dependencies: list[str] = []
    for category, detail, dependency_names, weight in AI_DEPENDENCY_RULES:
        matches = matcher(dependency_names)
        if not matches:
            continue
        matched_dependencies.extend(matches)
        if category == "ml_inference":
            matched_ml_dependencies.extend(matches)
        evidence.append(DetectionEvidence(category, path, f"{source_label} {detail}: {format_matches(matches)}", weight))
    if evidence:
        evidence.insert(
            0,
            DetectionEvidence(
                "ai_enabled",
                path,
                f"{source_label} AI dependency evidence: {format_matches(matched_dependencies)}",
                3,
            ),
        )
    if matched_ml_dependencies:
        evidence.insert(
            1,
            DetectionEvidence(
                "ml_enabled",
                path,
                f"{source_label} ML dependency evidence: {format_matches(matched_ml_dependencies)}",
                3,
            ),
        )
    return evidence


def ai_capability_evidence(path: str, category: str, detail: str, weight: int) -> list[DetectionEvidence]:
    evidence = [
        DetectionEvidence("ai_enabled", path, detail, 2),
        DetectionEvidence(category, path, detail, weight),
    ]
    if category == "ml_inference":
        evidence.insert(1, DetectionEvidence("ml_enabled", path, detail, 2))
    return evidence


def format_matches(matches: Iterable[str]) -> str:
    unique = sorted(set(matches))
    suffix = "" if len(unique) <= 6 else f" and {len(unique) - 6} more"
    return ", ".join(unique[:6]) + suffix


def detect_expo_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_expo_config(content)
    if metadata.name or metadata.version or metadata.identifier:
        return [DetectionEvidence("react_native", path, "Parsed Expo app config", 4)]
    return []


def detect_expo_dynamic_config_evidence(path: str, content: str) -> list[DetectionEvidence]:
    if re.search(r"\bexpo\s*:", content) and (
        regex_value(content, r"\bbundleIdentifier\s*:\s*['\"]([^'\"]+)")
        or regex_value(content, r"\bpackage\s*:\s*['\"]([^'\"]+)")
    ):
        return [DetectionEvidence("react_native", path, "Parsed Expo dynamic app config", 4)]
    return []


def detect_capacitor_json_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_capacitor_json(content)
    if metadata.identifier:
        return [DetectionEvidence("ionic_capacitor_cordova", path, f"Capacitor appId {metadata.identifier}", 4)]
    if metadata.name:
        return [DetectionEvidence("ionic_capacitor_cordova", path, "Parsed Capacitor app config", 2)]
    return []


def detect_capacitor_ts_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_capacitor_ts(content)
    if metadata.identifier:
        return [DetectionEvidence("ionic_capacitor_cordova", path, f"Capacitor appId {metadata.identifier}", 4)]
    if metadata.name:
        return [DetectionEvidence("ionic_capacitor_cordova", path, "Parsed Capacitor app config", 2)]
    return []


def detect_cordova_evidence(path: str, content: str) -> list[DetectionEvidence]:
    metadata = parse_cordova_config(content)
    if metadata.identifier:
        return [DetectionEvidence("ionic_capacitor_cordova", path, f"Cordova widget id {metadata.identifier}", 4)]
    return []


def detect_csproj_evidence(path: str, content: str) -> list[DetectionEvidence]:
    target_frameworks = " ".join((xml_text(content, "TargetFramework"), xml_text(content, "TargetFrameworks"))).lower()
    uses_maui = xml_text(content, "UseMaui").lower() == "true"
    evidence: list[DetectionEvidence] = []

    if uses_maui:
        evidence.append(DetectionEvidence("xamarin_maui", path, "UseMaui=true", 4))
    if "-android" in target_frameworks or "-ios" in target_frameworks or "-maccatalyst" in target_frameworks:
        evidence.append(
            DetectionEvidence("xamarin_maui", path, f"Mobile target frameworks: {target_frameworks}", 4)
        )
    metadata = parse_csproj(content)
    if metadata.identifier and (uses_maui or target_frameworks):
        evidence.append(DetectionEvidence("xamarin_maui", path, f".NET mobile ApplicationId {metadata.identifier}", 3))
    return evidence


def detect_pipeline_evidence(path: str, content: str) -> list[DetectionEvidence]:
    task_patterns = (
        r"\bXcode@\d+\b",
        r"\bGradle@\d+\b",
        r"\bAndroidSigning@\d+\b",
        r"\bInstallAppleCertificate@\d+\b",
        r"\bInstallAppleProvisioningProfile@\d+\b",
        r"\bGooglePlayRelease@\d+\b",
        r"\bAppStoreRelease@\d+\b",
    )
    count = sum(1 for pattern in task_patterns if re.search(pattern, content))
    if count >= 2:
        return [DetectionEvidence("pipeline_mobile", path, f"{count} mobile pipeline tasks", 2)]
    return []


def dedupe_evidence(evidence: list[DetectionEvidence]) -> list[DetectionEvidence]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[DetectionEvidence] = []
    for item in evidence:
        key = (item.category, item.source, item.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
