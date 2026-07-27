from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any

from .aspm_data import AssetDataInteraction, DATA_TYPE_LABELS
from .aspm_risk import AssetRiskContext


@dataclass(frozen=True, slots=True)
class AssetRiskProfile:
    score: int
    band: str
    technical_score: int
    data_sensitivity_score: int
    context_score: int
    active_findings: int
    critical_findings: int
    high_findings: int
    data_types: tuple[str, ...]
    factors: tuple[dict[str, Any], ...]


class AssetRiskProfileEngine:
    def assess(
        self,
        finding_scores: list[tuple[int, str]],
        interactions: tuple[AssetDataInteraction, ...],
        context: AssetRiskContext,
    ) -> AssetRiskProfile:
        technical = self._technical_score(finding_scores)
        data_sensitivity = self._data_sensitivity_score(interactions)
        context_score = self._context_score(context)
        inherent = round(data_sensitivity * 0.6 + context_score * 0.4)
        score = round(technical * 0.7 + inherent * 0.3)
        if finding_scores:
            score = max(score, min(max(item[0] for item in finding_scores), 95))
        score = max(0, min(score, 100))
        critical = sum(1 for _, severity in finding_scores if severity == "critical")
        high = sum(1 for _, severity in finding_scores if severity == "high")
        factors = (
            {
                "factor": "technical_findings",
                "score": technical,
                "activeFindings": len(finding_scores),
                "criticalFindings": critical,
                "highFindings": high,
            },
            {
                "factor": "data_sensitivity",
                "score": data_sensitivity,
                "dataTypes": [
                    {
                        "key": item.data_type,
                        "label": DATA_TYPE_LABELS.get(item.data_type, item.data_type),
                        "confidence": round(item.confidence, 3),
                        "findingCount": item.finding_count,
                    }
                    for item in interactions
                ],
            },
            {
                "factor": "asset_context",
                "score": context_score,
                "criticality": context.criticality,
                "internetExposed": context.internet_exposed,
                "dataClassification": context.data_classification,
            },
        )
        return AssetRiskProfile(
            score=score,
            band=risk_band(score),
            technical_score=technical,
            data_sensitivity_score=data_sensitivity,
            context_score=context_score,
            active_findings=len(finding_scores),
            critical_findings=critical,
            high_findings=high,
            data_types=tuple(item.data_type for item in interactions),
            factors=factors,
        )

    @staticmethod
    def _technical_score(finding_scores: list[tuple[int, str]]) -> int:
        if not finding_scores:
            return 0
        scores = sorted((score for score, _ in finding_scores), reverse=True)
        top = scores[:5]
        volume = min(12, round(math.log2(len(scores) + 1) * 3))
        return min(100, round(scores[0] * 0.65 + (sum(top) / len(top)) * 0.25 + volume))

    @staticmethod
    def _data_sensitivity_score(
        interactions: tuple[AssetDataInteraction, ...]
    ) -> int:
        if not interactions:
            return 0
        weighted = sorted(
            (item.weight * item.confidence for item in interactions), reverse=True
        )
        breadth = min(10, max(0, len(weighted) - 1) * 2)
        secondary = sum(weighted[1:4]) / max(1, len(weighted[1:4]))
        score = weighted[0] * 0.85 + secondary * 0.05 + breadth
        return min(100, round(score))

    @staticmethod
    def _context_score(context: AssetRiskContext) -> int:
        criticality = {
            "low": 15,
            "medium": 35,
            "high": 65,
            "mission_critical": 90,
        }.get(context.criticality, 35)
        classification = {
            "public": 5,
            "internal": 30,
            "confidential": 70,
            "restricted": 95,
        }.get(context.data_classification, 30)
        exposure = 100 if context.internet_exposed else 10
        return round(criticality * 0.35 + classification * 0.35 + exposure * 0.3)


def risk_band(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"
