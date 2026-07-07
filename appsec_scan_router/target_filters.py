from __future__ import annotations

import json
from typing import Any, Iterable

from .models import SourceTargetFilter
from .utils import clean_value_without_resource_filter


def parse_source_target_filter_values(values: Iterable[Any] | Any) -> tuple[SourceTargetFilter, ...]:
    if values is None:
        return ()
    candidates = (values,) if isinstance(values, dict) or isinstance(values, str | bytes) else values
    filters: dict[tuple[str, str], SourceTargetFilter] = {}
    for value in candidates:
        for target_filter in parse_source_target_filter_value(value):
            filters[(target_filter.org.lower(), target_filter.project.lower())] = target_filter
    return tuple(filters.values())


def parse_source_target_filter_value(value: Any) -> tuple[SourceTargetFilter, ...]:
    if value is None:
        return ()
    if isinstance(value, dict):
        project = value.get("project") or value.get("repo") or value.get("repository") or value.get("name")
        org = value.get("org") or value.get("organization") or value.get("owner")
        if org or project:
            target_filter = make_source_target_filter(org, project)
            return (target_filter,) if target_filter else ()
        parsed: list[SourceTargetFilter] = []
        for org_key, projects in value.items():
            if isinstance(projects, list | tuple | set):
                for project in projects:
                    target_filter = make_source_target_filter(org_key, project)
                    if target_filter:
                        parsed.append(target_filter)
            else:
                target_filter = make_source_target_filter(org_key, projects)
                if target_filter:
                    parsed.append(target_filter)
        return tuple(parsed)
    if isinstance(value, list | tuple | set):
        return parse_source_target_filter_sequence(value)
    text = clean_value_without_resource_filter(value)
    if not text:
        return ()
    if text.startswith("{") or text.startswith("["):
        try:
            return parse_source_target_filter_value(json.loads(text))
        except ValueError as exc:
            raise ValueError("Target filter JSON is invalid.") from exc
    return parse_source_target_filter_sequence(split_source_target_filter_text(text))


def parse_source_target_filter_sequence(values: Iterable[Any]) -> tuple[SourceTargetFilter, ...]:
    parsed: list[SourceTargetFilter] = []
    for value in values:
        if isinstance(value, dict):
            parsed.extend(parse_source_target_filter_value(value))
            continue
        text = clean_value_without_resource_filter(value)
        if not text:
            continue
        org = ""
        project = text
        if "=" in text:
            org, project = text.split("=", 1)
        target_filter = make_source_target_filter(org, project)
        if target_filter:
            parsed.append(target_filter)
    return tuple(parsed)


def split_source_target_filter_text(text: str) -> list[str]:
    entries: list[str] = []
    for line in text.replace(";", "\n").splitlines():
        for value in line.split(","):
            cleaned = value.strip()
            if cleaned:
                entries.append(cleaned)
    return entries


def make_source_target_filter(org: Any, project: Any) -> SourceTargetFilter | None:
    org_value = clean_value_without_resource_filter(org)
    project_value = clean_value_without_resource_filter(project)
    if not org_value and not project_value:
        return None
    if not project_value:
        raise ValueError("Target filters must include a project or repository name.")
    return SourceTargetFilter(org=org_value, project=project_value)


def source_target_filters_to_json(target_filters: Iterable[SourceTargetFilter | dict[str, Any]]) -> str:
    values = []
    for item in target_filters:
        if isinstance(item, SourceTargetFilter):
            org = item.org
            project = item.project
        else:
            org = clean_value_without_resource_filter(item.get("org") or item.get("organization") or item.get("owner"))
            project = clean_value_without_resource_filter(
                item.get("project") or item.get("repo") or item.get("repository") or item.get("name")
            )
        if project:
            values.append({"org": org, "project": project})
    return json.dumps(values)


def target_filter_value(target_filter: SourceTargetFilter | dict[str, Any]) -> str:
    if isinstance(target_filter, SourceTargetFilter):
        org = target_filter.org
        project = target_filter.project
    else:
        org = clean_value_without_resource_filter(target_filter.get("org"))
        project = clean_value_without_resource_filter(target_filter.get("project"))
    return f"{org}={project}" if org else project
