from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from .aspm_models import FindingInput, RiskAssessment, normalize_severity


@dataclass(frozen=True, slots=True)
class AssetRiskContext:
    criticality: str = "medium"
    internet_exposed: bool = False
    data_classification: str = "internal"


class RiskEngine:
    severity_scores = {
        "critical": 48,
        "high": 36,
        "medium": 24,
        "low": 12,
        "info": 3,
    }
    criticality_scores = {
        "mission_critical": 15,
        "high": 10,
        "medium": 5,
        "low": 0,
    }
    classification_scores = {
        "restricted": 10,
        "confidential": 7,
        "internal": 2,
        "public": 0,
    }

    def assess(
        self,
        finding: FindingInput,
        context: AssetRiskContext | None = None,
        now: datetime | None = None,
    ) -> RiskAssessment:
        asset = context or AssetRiskContext()
        factors: list[dict[str, int | float | str | bool]] = []
        severity = normalize_severity(finding.severity)
        score = self.severity_scores[severity]
        factors.append({"factor": "severity", "value": severity, "points": score})

        if finding.cvss_score is not None:
            points = min(12, round(finding.cvss_score * 1.2))
            score += points
            factors.append(
                {"factor": "cvss", "value": finding.cvss_score, "points": points}
            )

        if finding.epss_score is not None:
            normalized_epss = (
                finding.epss_score / 100
                if finding.epss_score > 1
                else finding.epss_score
            )
            points = min(10, round(normalized_epss * 10))
            score += points
            factors.append(
                {"factor": "epss", "value": round(normalized_epss, 4), "points": points}
            )

        if finding.exploit_available:
            score += 12
            factors.append({"factor": "known_exploit", "value": True, "points": 12})

        if asset.internet_exposed:
            score += 10
            factors.append({"factor": "internet_exposed", "value": True, "points": 10})

        criticality = (
            asset.criticality
            if asset.criticality in self.criticality_scores
            else "medium"
        )
        criticality_points = self.criticality_scores[criticality]
        score += criticality_points
        factors.append(
            {
                "factor": "asset_criticality",
                "value": criticality,
                "points": criticality_points,
            }
        )

        classification = (
            asset.data_classification
            if asset.data_classification in self.classification_scores
            else "internal"
        )
        classification_points = self.classification_scores[classification]
        score += classification_points
        factors.append(
            {
                "factor": "data_classification",
                "value": classification,
                "points": classification_points,
            }
        )

        observed = finding.first_seen or finding.last_seen
        if observed:
            reference = now or datetime.now(timezone.utc)
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=timezone.utc)
            age_days = max(0, (reference - observed).days)
            age_points = min(8, age_days // 30)
            if age_points:
                score += age_points
                factors.append(
                    {
                        "factor": "finding_age_days",
                        "value": age_days,
                        "points": age_points,
                    }
                )

        bounded_score = max(0, min(100, int(score)))
        return RiskAssessment(
            score=bounded_score,
            band=self.band(bounded_score),
            factors=tuple(factors),
        )

    @staticmethod
    def band(score: int) -> str:
        if score >= 85:
            return "critical"
        if score >= 65:
            return "high"
        if score >= 35:
            return "medium"
        return "low"
