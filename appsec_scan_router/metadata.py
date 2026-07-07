from __future__ import annotations

import plistlib
import re
from typing import Any

from defusedxml import ElementTree

from .models import MobileAppMetadata
from .utils import (
    clean_value,
    clean_value_without_resource_filter,
    clean_version,
    first_present,
    load_json_object,
    regex_value,
    xml_text,
    yaml_scalar,
)


def extract_mobile_metadata(file_contents: dict[str, str]) -> MobileAppMetadata:
    candidates: list[tuple[int, MobileAppMetadata]] = []
    android_strings = collect_android_strings(file_contents)
    properties = collect_metadata_properties(file_contents)

    for path, content in file_contents.items():
        lower_path = path.lower()
        metadata = MobileAppMetadata()
        priority = 100

        if lower_path.endswith("info.plist"):
            metadata = parse_info_plist(content, properties)
            priority = 10
        elif lower_path.endswith("infoplist.strings"):
            metadata = parse_info_plist_strings(content)
            priority = 12
        elif lower_path.endswith("project.pbxproj") or lower_path.endswith(".xcconfig"):
            metadata = parse_xcode_settings_metadata(content)
            priority = 15
        elif lower_path.endswith("androidmanifest.xml"):
            metadata = parse_android_manifest(content, android_strings)
            priority = 20
        elif lower_path.endswith("capacitor.config.json"):
            metadata = parse_capacitor_json(content)
            priority = 25
        elif lower_path.endswith("capacitor.config.ts"):
            metadata = parse_capacitor_ts(content)
            priority = 25
        elif lower_path.endswith("config.xml"):
            metadata = parse_cordova_config(content)
            priority = 30
        elif lower_path.endswith("app.json") or lower_path.endswith("expo.json"):
            metadata = parse_expo_config(content)
            priority = 35
        elif lower_path.endswith("app.config.js") or lower_path.endswith("app.config.ts"):
            metadata = parse_expo_dynamic_config(content)
            priority = 35
        elif lower_path.endswith("build.gradle") or lower_path.endswith("build.gradle.kts"):
            metadata = parse_gradle_metadata(content, properties)
            priority = 45
        elif lower_path.endswith("pubspec.yaml"):
            metadata = parse_pubspec(content)
            priority = 60
        elif lower_path.endswith("package.json"):
            metadata = parse_package_json(content)
            priority = 70
        elif lower_path.endswith(".csproj"):
            metadata = parse_csproj(content, properties)
            priority = 75
        elif lower_path.endswith(".props"):
            metadata = parse_msbuild_props(content)
            priority = 80

        if metadata.name or metadata.version or metadata.identifier:
            candidates.append((priority, metadata))

    if not candidates:
        return MobileAppMetadata()

    candidates.sort(key=lambda item: item[0])
    identifier_source = first_present(
        metadata.identifier_source
        for _, metadata in candidates
        if clean_value(metadata.identifier)
    )
    return MobileAppMetadata(
        name=first_present(metadata.name for _, metadata in candidates),
        version=first_present(metadata.version for _, metadata in candidates),
        identifier=first_present(metadata.identifier for _, metadata in candidates),
        identifier_source=identifier_source,
    )


def collect_metadata_properties(file_contents: dict[str, str]) -> dict[str, str]:
    properties: dict[str, str] = {}
    for path, content in file_contents.items():
        lower_path = path.lower()
        if lower_path.endswith("gradle.properties"):
            properties.update(parse_properties_file(content))
        elif lower_path.endswith(".xcconfig") or lower_path.endswith("project.pbxproj"):
            properties.update(parse_xcode_settings(content))
        elif lower_path.endswith(".props") or lower_path.endswith(".csproj"):
            properties.update(parse_msbuild_properties(content))
    return properties


def parse_properties_file(content: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("!", "#")):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            continue
        properties[clean_value(key)] = clean_value(value)
    return {key: value for key, value in properties.items() if key and value}


def parse_xcode_settings(content: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    pattern = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;\n]+)\s*;?", re.MULTILINE)
    for match in pattern.finditer(content):
        key = clean_value(match.group(1))
        value = clean_value(match.group(2))
        if key and value:
            settings[key] = value
    return settings


def parse_msbuild_properties(content: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    pattern = re.compile(r"<(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)>\s*(?P<value>[^<]+?)\s*</(?P=key)>")
    for match in pattern.finditer(content):
        key = clean_value(match.group("key"))
        value = clean_value(match.group("value"))
        if key and value:
            properties[key] = value
    return properties


def resolve_property_value(value: Any, properties: dict[str, str]) -> str:
    raw_value = clean_value_without_resource_filter(value)
    if not raw_value:
        return ""
    if "$(" in raw_value:
        resolved = raw_value
        for key in re.findall(r"\$\(([^)]+)\)", raw_value):
            replacement = properties.get(key, "")
            if not replacement:
                return ""
            resolved = resolved.replace(f"$({key})", replacement)
        return clean_value(resolved)
    if "${" in raw_value:
        resolved = raw_value
        for key in re.findall(r"\$\{([^}]+)\}", raw_value):
            replacement = properties.get(key, "")
            if not replacement:
                return ""
            resolved = resolved.replace(f"${{{key}}}", replacement)
        return clean_value(resolved)
    if raw_value in properties:
        return clean_value(properties[raw_value])
    last_segment = raw_value.rsplit(".", 1)[-1]
    if last_segment in properties:
        return clean_value(properties[last_segment])
    return clean_value(raw_value)


def parse_info_plist(content: str, properties: dict[str, str] | None = None) -> MobileAppMetadata:
    try:
        data = plistlib.loads(content.encode("utf-8"))
    except Exception:
        data = parse_plist_like_text(content)

    if not isinstance(data, dict):
        return MobileAppMetadata()

    identifier = resolve_property_value(data.get("CFBundleIdentifier", ""), properties or {})
    return MobileAppMetadata(
        name=first_present(
            (
                data.get("CFBundleDisplayName", ""),
                data.get("CFBundleName", ""),
                data.get("CFBundleExecutable", ""),
            )
        ),
        version=clean_version(data.get("CFBundleShortVersionString", "")),
        identifier=identifier,
        identifier_source="Info.plist" if identifier else "",
    )


def parse_plist_like_text(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    pattern = re.compile(
        r"<key>(?P<key>[^<]+)</key>\s*<(?:string|integer|real)>(?P<value>[^<]*)</",
        re.IGNORECASE,
    )
    for match in pattern.finditer(content):
        values[match.group("key")] = match.group("value")
    return values


def parse_info_plist_strings(content: str) -> MobileAppMetadata:
    return MobileAppMetadata(
        name=first_present(
            (
                apple_strings_value(content, "CFBundleDisplayName"),
                apple_strings_value(content, "CFBundleName"),
            )
        )
    )


def apple_strings_value(content: str, key: str) -> str:
    return regex_value(content, rf'"{re.escape(key)}"\s*=\s*"([^"]+)"')


def parse_xcode_settings_metadata(content: str) -> MobileAppMetadata:
    identifier = xcode_setting_value(content, "PRODUCT_BUNDLE_IDENTIFIER")
    return MobileAppMetadata(
        name=xcode_setting_value(content, "PRODUCT_NAME"),
        version=clean_version(xcode_setting_value(content, "MARKETING_VERSION")),
        identifier=identifier,
        identifier_source="Xcode build settings" if identifier else "",
    )


def xcode_setting_value(content: str, key: str) -> str:
    pattern = rf"^\s*{re.escape(key)}\s*=\s*([^;\n]+)\s*;?"
    for match in re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE):
        value = clean_value(match.group(1))
        if value:
            return value
    return ""


def collect_android_strings(file_contents: dict[str, str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for path, content in file_contents.items():
        if not path.lower().endswith("strings.xml"):
            continue
        try:
            root = ElementTree.fromstring(content)
        except ElementTree.ParseError:
            continue
        for node in root.findall("string"):
            name = clean_value(node.get("name", ""))
            value = clean_value(node.text or "")
            if name and value:
                values[name] = value
    return values


def parse_android_manifest(
    content: str,
    string_resources: dict[str, str] | None = None,
) -> MobileAppMetadata:
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        identifier = regex_value(content, r'package\s*=\s*["\']([^"\']+)')
        return MobileAppMetadata(
            version=clean_version(regex_value(content, r'android:versionName\s*=\s*["\']([^"\']+)')),
            identifier=identifier,
            identifier_source="AndroidManifest.xml" if identifier else "",
        )

    android_ns = "{http://schemas.android.com/apk/res/android}"
    application = root.find("application")
    raw_label = application.get(f"{android_ns}label") if application is not None else ""
    identifier = clean_value(root.get("package", ""))
    return MobileAppMetadata(
        name=resolve_android_label(raw_label, string_resources or {}),
        version=clean_version(root.get(f"{android_ns}versionName", "")),
        identifier=identifier,
        identifier_source="AndroidManifest.xml" if identifier else "",
    )


def resolve_android_label(label: str | None, string_resources: dict[str, str]) -> str:
    label = clean_value_without_resource_filter(label)
    if not label:
        return ""
    if label.startswith("@string/"):
        return clean_value(string_resources.get(label.removeprefix("@string/"), ""))
    return clean_value(label)


def parse_capacitor_json(content: str) -> MobileAppMetadata:
    data = load_json_object(content)
    identifier = clean_value(data.get("appId", ""))
    return MobileAppMetadata(
        name=clean_value(data.get("appName", "")),
        version=clean_version(data.get("version", "")),
        identifier=identifier,
        identifier_source="capacitor.config.json" if identifier else "",
    )


def parse_capacitor_ts(content: str) -> MobileAppMetadata:
    identifier = regex_value(content, r"\bappId\s*:\s*['\"]([^'\"]+)")
    return MobileAppMetadata(
        name=regex_value(content, r"\bappName\s*:\s*['\"]([^'\"]+)"),
        version=clean_version(regex_value(content, r"\bversion\s*:\s*['\"]([^'\"]+)")),
        identifier=identifier,
        identifier_source="capacitor.config.ts" if identifier else "",
    )


def parse_cordova_config(content: str) -> MobileAppMetadata:
    try:
        root = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        identifier = regex_value(content, r'\bid\s*=\s*["\']([^"\']+)')
        return MobileAppMetadata(
            name=regex_value(content, r"<name>\s*([^<]+?)\s*</name>"),
            version=clean_version(regex_value(content, r'\bversion\s*=\s*["\']([^"\']+)')),
            identifier=identifier,
            identifier_source="Cordova config.xml" if identifier else "",
        )

    name_node = root.find("name")
    if name_node is None:
        name_node = root.find("{http://www.w3.org/ns/widgets}name")

    identifier = clean_value(root.get("id", ""))
    return MobileAppMetadata(
        name=clean_value(name_node.text if name_node is not None else ""),
        version=clean_version(root.get("version", "")),
        identifier=identifier,
        identifier_source="Cordova config.xml" if identifier else "",
    )


def parse_expo_config(content: str) -> MobileAppMetadata:
    data = load_json_object(content)
    expo = data.get("expo") if isinstance(data.get("expo"), dict) else data
    ios = expo.get("ios") if isinstance(expo.get("ios"), dict) else {}
    android = expo.get("android") if isinstance(expo.get("android"), dict) else {}

    identifier = first_present(
        (
            ios.get("bundleIdentifier", ""),
            android.get("package", ""),
        )
    )
    return MobileAppMetadata(
        name=clean_value(expo.get("name", "")),
        version=clean_version(expo.get("version", "")),
        identifier=identifier,
        identifier_source="Expo app config" if identifier else "",
    )


def parse_expo_dynamic_config(content: str) -> MobileAppMetadata:
    identifier = first_present(
        (
            regex_value(content, r"\bbundleIdentifier\s*:\s*['\"]([^'\"]+)"),
            regex_value(content, r"\bpackage\s*:\s*['\"]([^'\"]+)"),
        )
    )
    return MobileAppMetadata(
        name=regex_value(content, r"\bname\s*:\s*['\"]([^'\"]+)"),
        version=clean_version(regex_value(content, r"\bversion\s*:\s*['\"]([^'\"]+)")),
        identifier=identifier,
        identifier_source="Expo dynamic config" if identifier else "",
    )


def parse_gradle_metadata(content: str, properties: dict[str, str] | None = None) -> MobileAppMetadata:
    raw_identifier = (
        gradle_assignment_value(content, "applicationId")
        or gradle_assignment_value(content, "namespace")
    )
    identifier = resolve_property_value(
        raw_identifier,
        properties or {},
    )
    return MobileAppMetadata(
        version=clean_version(regex_value(content, r"\bversionName\s*(?:=|\s)\s*['\"]([^'\"]+)")),
        identifier=identifier,
        identifier_source="Gradle applicationId/namespace" if identifier else "",
    )


def gradle_assignment_value(content: str, key: str) -> str:
    patterns = (
        rf"\b{re.escape(key)}\s*(?:=|\s)\s*project\.property\(['\"]([^'\"]+)['\"]\)",
        rf"\b{re.escape(key)}\s*(?:=|\s)\s*['\"]([^'\"]+)['\"]",
        rf"\b{re.escape(key)}\s*(?:=|\s)\s*([A-Za-z_][A-Za-z0-9_.-]*)",
    )
    for pattern in patterns:
        match = re.search(pattern, content)
        if match:
            return clean_value_without_resource_filter(match.group(1))
    return ""


def parse_pubspec(content: str) -> MobileAppMetadata:
    return MobileAppMetadata(
        name=yaml_scalar(content, "name"),
        version=clean_version(yaml_scalar(content, "version")),
    )


def parse_package_json(content: str) -> MobileAppMetadata:
    data = load_json_object(content)
    return MobileAppMetadata(
        name=clean_value(data.get("displayName") or data.get("name", "")),
        version=clean_version(data.get("version", "")),
    )


def parse_csproj(content: str, properties: dict[str, str] | None = None) -> MobileAppMetadata:
    identifier = first_present(
        (
            resolve_property_value(xml_text(content, "ApplicationId"), properties or {}),
            resolve_property_value(xml_text(content, "ApplicationIdGuid"), properties or {}),
        )
    )
    return MobileAppMetadata(
        name=first_present(
            (
                xml_text(content, "ApplicationTitle"),
                xml_text(content, "AssemblyName"),
            )
        ),
        version=first_present(
            (
                clean_version(xml_text(content, "ApplicationDisplayVersion")),
                clean_version(xml_text(content, "Version")),
            )
        ),
        identifier=identifier,
        identifier_source=".csproj ApplicationId" if identifier else "",
    )


def parse_msbuild_props(content: str) -> MobileAppMetadata:
    properties = parse_msbuild_properties(content)
    identifier = first_present(
        (
            properties.get("ApplicationId", ""),
            properties.get("ApplicationIdGuid", ""),
        )
    )
    return MobileAppMetadata(
        version=clean_version(properties.get("ApplicationDisplayVersion", "")),
        identifier=identifier,
        identifier_source="MSBuild props" if identifier else "",
    )
