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


@dataclass(frozen=True, slots=True)
class AssetFindingSummary:
    active_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    top_scores: tuple[int, ...] = ()

    @classmethod
    def from_findings(
        cls, finding_scores: list[tuple[int, str]]
    ) -> AssetFindingSummary:
        return cls(
            active_findings=len(finding_scores),
            critical_findings=sum(
                1 for _, severity in finding_scores if severity == "critical"
            ),
            high_findings=sum(
                1 for _, severity in finding_scores if severity == "high"
            ),
            top_scores=tuple(
                sorted((score for score, _ in finding_scores), reverse=True)[:5]
            ),
        )


class AssetRiskProfileEngine:
    def assess(
        self,
        finding_scores: list[tuple[int, str]],
        interactions: tuple[AssetDataInteraction, ...],
        context: AssetRiskContext,
    ) -> AssetRiskProfile:
        return self.assess_summary(
            AssetFindingSummary.from_findings(finding_scores),
            interactions,
            context,
        )

    def assess_summary(
        self,
        summary: AssetFindingSummary,
        interactions: tuple[AssetDataInteraction, ...],
        context: AssetRiskContext,
    ) -> AssetRiskProfile:
        technical = self._technical_score(summary)
        data_sensitivity = self._data_sensitivity_score(interactions)
        context_score = self._context_score(context)
        inherent = round(data_sensitivity * 0.6 + context_score * 0.4)
        score = round(technical * 0.7 + inherent * 0.3)
        if summary.top_scores:
            score = max(score, min(summary.top_scores[0], 95))
        score = max(0, min(score, 100))
        factors = (
            {
                "factor": "technical_findings",
                "score": technical,
                "activeFindings": summary.active_findings,
                "criticalFindings": summary.critical_findings,
                "highFindings": summary.high_findings,
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
            active_findings=summary.active_findings,
            critical_findings=summary.critical_findings,
            high_findings=summary.high_findings,
            data_types=tuple(item.data_type for item in interactions),
            factors=factors,
        )

    @staticmethod
    def _technical_score(summary: AssetFindingSummary) -> int:
        if not summary.active_findings or not summary.top_scores:
            return 0
        volume = min(12, round(math.log2(summary.active_findings + 1) * 3))
        average = sum(summary.top_scores) / len(summary.top_scores)
        return min(
            100,
            round(summary.top_scores[0] * 0.65 + average * 0.25 + volume),
        )

    @staticmethod
    def _data_sensitivity_score(interactions: tuple[AssetDataInteraction, ...]) -> int:
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
