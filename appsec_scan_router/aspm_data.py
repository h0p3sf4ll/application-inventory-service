from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .aspm_models import DataInteraction, FindingInput, bounded_text, clean_identity


DATA_TYPE_WEIGHTS = {
    "authentication_data": 92,
    "biometric_data": 100,
    "confidential_business_data": 72,
    "credentials": 96,
    "device_identifiers": 55,
    "financial_data": 90,
    "health_data": 100,
    "location_data": 78,
    "payment_card_data": 100,
    "personal_data": 82,
    "secrets": 98,
    "source_code": 68,
    "tracking_data": 58,
}

DATA_TYPE_LABELS = {
    "authentication_data": "Authentication data",
    "biometric_data": "Biometric data",
    "confidential_business_data": "Confidential business data",
    "credentials": "Credentials",
    "device_identifiers": "Device identifiers",
    "financial_data": "Financial data",
    "health_data": "Health data",
    "location_data": "Location data",
    "payment_card_data": "Payment card data",
    "personal_data": "Personal data",
    "secrets": "Secrets",
    "source_code": "Source code",
    "tracking_data": "Tracking data",
}

DATA_TYPE_ALIASES = {
    "auth": "authentication_data",
    "authentication": "authentication_data",
    "authentication_data": "authentication_data",
    "biometric": "biometric_data",
    "biometrics": "biometric_data",
    "business_confidential": "confidential_business_data",
    "confidential": "confidential_business_data",
    "credential": "credentials",
    "credentials": "credentials",
    "device_id": "device_identifiers",
    "device_identifiers": "device_identifiers",
    "financial": "financial_data",
    "financial_data": "financial_data",
    "health": "health_data",
    "health_data": "health_data",
    "location": "location_data",
    "location_data": "location_data",
    "payment": "payment_card_data",
    "payment_card": "payment_card_data",
    "payment_card_data": "payment_card_data",
    "personal": "personal_data",
    "personal_data": "personal_data",
    "pii": "personal_data",
    "secret": "secrets",
    "secrets": "secrets",
    "source": "source_code",
    "source_code": "source_code",
    "tracking": "tracking_data",
    "tracking_data": "tracking_data",
}

CWE_DATA_TYPES = {
    "CWE-200": ("confidential_business_data", "personal_data"),
    "CWE-201": ("personal_data",),
    "CWE-209": ("confidential_business_data",),
    "CWE-256": ("credentials",),
    "CWE-257": ("credentials",),
    "CWE-259": ("credentials",),
    "CWE-311": ("confidential_business_data",),
    "CWE-312": ("confidential_business_data",),
    "CWE-319": ("confidential_business_data", "authentication_data"),
    "CWE-359": ("personal_data",),
    "CWE-522": ("credentials", "authentication_data"),
    "CWE-532": ("secrets", "personal_data"),
    "CWE-538": ("source_code", "confidential_business_data"),
    "CWE-598": ("authentication_data", "personal_data"),
    "CWE-614": ("authentication_data",),
    "CWE-639": ("personal_data",),
    "CWE-798": ("credentials", "secrets"),
}

STRUCTURED_PATTERNS = (
    (
        "payment_card_data",
        re.compile(
            r"\b(?:payment card|credit card|cardholder|pci(?:[- ]?dss)?)\b", re.I
        ),
    ),
    (
        "health_data",
        re.compile(r"\b(?:health data|medical record|patient data|phi|hipaa)\b", re.I),
    ),
    (
        "biometric_data",
        re.compile(r"\b(?:biometric|faceprint|fingerprint data|voiceprint)\b", re.I),
    ),
    (
        "credentials",
        re.compile(r"\b(?:credential|password|passcode|private key|api key)\b", re.I),
    ),
    (
        "secrets",
        re.compile(r"\b(?:secret|token exposure|hardcoded key|private key)\b", re.I),
    ),
    (
        "authentication_data",
        re.compile(
            r"\b(?:authentication|session token|access token|refresh token|oauth)\b",
            re.I,
        ),
    ),
    (
        "financial_data",
        re.compile(
            r"\b(?:financial data|bank account|routing number|transaction data)\b",
            re.I,
        ),
    ),
    (
        "personal_data",
        re.compile(
            r"\b(?:personal data|personally identifiable|privacy|email address|"
            r"phone number|social security|gdpr)\b",
            re.I,
        ),
    ),
    (
        "location_data",
        re.compile(r"\b(?:precise location|geolocation|gps|location data)\b", re.I),
    ),
    (
        "device_identifiers",
        re.compile(
            r"\b(?:device identifier|advertising id|idfa|android id|imei)\b", re.I
        ),
    ),
    (
        "tracking_data",
        re.compile(
            r"\b(?:user tracking|cross[- ]app tracking|analytics identifier|"
            r"tracking data)\b",
            re.I,
        ),
    ),
    (
        "source_code",
        re.compile(r"\b(?:source code|repository content|proprietary code)\b", re.I),
    ),
    (
        "confidential_business_data",
        re.compile(
            r"\b(?:confidential data|sensitive information|business confidential|"
            r"trade secret)\b",
            re.I,
        ),
    ),
)

STRUCTURED_KEYS = frozenset(
    {
        "categories",
        "category",
        "classification",
        "classifications",
        "cwe",
        "cwe_names",
        "data_category",
        "data_classification",
        "data_type",
        "data_types",
        "owasp_names",
        "privacy_category",
        "regulations",
        "subcategory",
        "subcategories",
        "vulnerability_classes",
    }
)


@dataclass(frozen=True, slots=True)
class AssetDataInteraction:
    data_type: str
    confidence: float
    finding_count: int
    evidence: tuple[dict[str, Any], ...]

    @property
    def weight(self) -> int:
        return DATA_TYPE_WEIGHTS.get(self.data_type, 50)


class DataInteractionClassifier:
    def classify(self, finding: FindingInput) -> tuple[DataInteraction, ...]:
        candidates: dict[str, DataInteraction] = {}
        for interaction in finding.data_interactions:
            self._add(candidates, interaction)
        for cwe in finding.cwes:
            for data_type in CWE_DATA_TYPES.get(cwe.upper(), ()):
                self._add(
                    candidates,
                    DataInteraction(data_type, 0.85, "cwe", cwe.upper()),
                )
        for label in structured_labels(finding.raw_data):
            for data_type, pattern in STRUCTURED_PATTERNS:
                if pattern.search(label):
                    self._add(
                        candidates,
                        DataInteraction(data_type, 0.9, "scanner_metadata", label),
                    )
        text = " ".join(
            value
            for value in (
                finding.title,
                finding.description,
                finding.category,
                finding.rule_id,
            )
            if value
        )
        for data_type, pattern in STRUCTURED_PATTERNS:
            match = pattern.search(text)
            if match:
                self._add(
                    candidates,
                    DataInteraction(
                        data_type,
                        0.65,
                        "finding_text",
                        bounded_text(match.group(0), 300),
                    ),
                )
        return tuple(sorted(candidates.values(), key=lambda item: item.data_type))

    @staticmethod
    def _add(
        candidates: dict[str, DataInteraction], interaction: DataInteraction
    ) -> None:
        data_type = normalize_data_type(interaction.data_type)
        if not data_type:
            return
        confidence = max(0.0, min(float(interaction.confidence), 1.0))
        candidate = DataInteraction(
            data_type=data_type,
            confidence=confidence,
            source=bounded_text(interaction.source, 100) or "scanner",
            evidence=bounded_text(interaction.evidence, 500),
        )
        current = candidates.get(data_type)
        if current is None or candidate.confidence > current.confidence:
            candidates[data_type] = candidate


def normalize_data_type(value: Any) -> str:
    normalized = clean_identity(value)
    canonical = DATA_TYPE_ALIASES.get(normalized, normalized)
    return canonical if canonical in DATA_TYPE_WEIGHTS else ""


def explicit_data_interactions(
    values: Iterable[Any], source: str, confidence: float = 0.95
) -> tuple[DataInteraction, ...]:
    interactions: dict[str, DataInteraction] = {}
    for value in values:
        label = bounded_text(value, 500)
        if not label:
            continue
        direct = normalize_data_type(label)
        if direct:
            interactions[direct] = DataInteraction(direct, confidence, source, label)
        for data_type, pattern in STRUCTURED_PATTERNS:
            if pattern.search(label):
                interactions[data_type] = DataInteraction(
                    data_type, confidence, source, label
                )
    return tuple(sorted(interactions.values(), key=lambda item: item.data_type))


def structured_labels(value: Any, parent_key: str = "") -> tuple[str, ...]:
    labels: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized_key = clean_identity(key)
            if normalized_key in STRUCTURED_KEYS:
                labels.extend(flatten_text(item))
            elif isinstance(item, Mapping):
                labels.extend(structured_labels(item, normalized_key))
            elif isinstance(item, (list, tuple)) and normalized_key in {
                "rule",
                "check",
                "issue",
            }:
                labels.extend(structured_labels(item, normalized_key))
    elif isinstance(value, (list, tuple)):
        for item in value:
            labels.extend(structured_labels(item, parent_key))
    return tuple(dict.fromkeys(bounded_text(item, 500) for item in labels if item))


def flatten_text(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [
            bounded_text(item, 500)
            for item in value.values()
            if isinstance(item, (str, int, float)) and bounded_text(item, 500)
        ]
    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        for item in value:
            result.extend(flatten_text(item))
        return result
    text = bounded_text(value, 500)
    return [text] if text else []
