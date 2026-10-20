"""Static safety and completeness checks for the decoy catalogue."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from typing import Any

URL_HOST_RE = re.compile(
    r"\b(?:https?|postgresql)://(?:[^@\s/]+@)?(?P<host>[a-z0-9.-]+)",
    re.IGNORECASE,
)
EMAIL_DOMAIN_RE = re.compile(r"\b[A-Z0-9._%+-]+@(?P<host>[A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
HOST_FIELD_RE = re.compile(
    r"""["'](?:host|endpoint)["']\s*:\s*["'](?P<host>[a-z0-9.-]+\.[a-z]{2,})["']""",
    re.IGNORECASE,
)
FILE_REFERENCE_RE = re.compile(r"/files/([A-Za-z0-9._/-]+)")
DATE_RE = re.compile(r"\b(20\d{2})-(0[1-9]|1[0-2])(?:-(0[1-9]|[12]\d|3[01]))?\b")
HOST_RE = re.compile(r"\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.invalid)\b", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b([a-z0-9._%+-]+)@([a-z0-9.-]+\.[a-z]{2,})\b", re.IGNORECASE)
BRAND_TOKEN_RE = re.compile(r"\b(homerdrive-[a-z0-9-]+)\b")
SHIPPER_HOST_RE = re.compile(r"shipper-[a-z0-9-]+\.invalid")
STAFF_LOCALS = {"a.rivera", "m.chen", "s.kim"}
ALLOWED_BRAND_TOKENS = {
    "homerdrive-staging",
    "homerdrive-freight-archive-staging",
    "homerdrive-dispatch-backups",
}
TIMELINE_MIN = 2016 * 12 + 1
TIMELINE_MAX = 2026 * 12 + 10
REQUIRED_TIMELINE_MARKS = {
    "incident_note": ("2025-11", "2026-04"),
    "credential_rotation": ("2026-07", "2026-10"),
    "ssh_backup": ("2025-11",),
}
SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
}
REQUIRED_FIELDS = (
    "id",
    "category",
    "path",
    "media_type",
    "prompt",
    "provenance",
    "manual_curation_notes",
    "baseline",
    "enhanced",
)
SAFE_CREDENTIAL_MARKERS = (".invalid", "invalid_", "invalid-", "placeholder", "retired")


def validate_decoys(decoys: Sequence[Any]) -> list[str]:
    """Return human-readable validation errors without mutating the catalogue."""
    errors: list[str] = []
    if len(decoys) < 10:
        errors.append("catalogue must contain at least 10 artefacts")
    categories = {getattr(item, "category", None) for item in decoys}
    categories.discard(None)
    if len(categories) < 3:
        errors.append("catalogue must contain at least 3 categories")
    curated = sum(bool(getattr(item, "llm_curated", False)) for item in decoys)
    if curated < 5:
        errors.append("catalogue must contain at least 5 llm_curated artefacts")

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    allowed_paths = {getattr(item, "path", "") for item in decoys}
    for index, item in enumerate(decoys):
        label = getattr(item, "id", None) or f"item[{index}]"
        for field in REQUIRED_FIELDS:
            value = getattr(item, field, None)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}: required field {field} is blank")
        if not isinstance(getattr(item, "llm_curated", None), bool):
            errors.append(f"{label}: llm_curated must be a boolean generation record")
        item_id = getattr(item, "id", "")
        path = getattr(item, "path", "")
        if item_id in seen_ids:
            errors.append(f"{label}: duplicate id")
        if path in seen_paths:
            errors.append(f"{label}: duplicate path")
        seen_ids.add(item_id)
        seen_paths.add(path)
        if path.startswith("/") or ".." in path.split("/"):
            errors.append(f"{label}: path must be a safe relative path")

        bodies = f"{getattr(item, 'baseline', '')}\n{getattr(item, 'enhanced', '')}"
        for reference in FILE_REFERENCE_RE.findall(bodies):
            reference = reference.rstrip(".,;:")
            if reference not in allowed_paths:
                errors.append(f"{label}: unknown file reference: {reference}")
        if getattr(item, "media_type", "") == "application/json":
            for condition in ("baseline", "enhanced"):
                try:
                    json.loads(getattr(item, condition, ""))
                except json.JSONDecodeError:
                    errors.append(f"{label}: invalid JSON in {condition}")
        network_hosts = [
            match.group("host")
            for pattern in (URL_HOST_RE, EMAIL_DOMAIN_RE, HOST_FIELD_RE)
            for match in pattern.finditer(bodies)
        ]
        for host in network_hosts:
            if not host.lower().endswith(".invalid"):
                errors.append(f"{label}: non-reserved domain found: {host}")
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(bodies):
                errors.append(f"{label}: possible real {name} pattern")
        # Internal consistency: dates inside the agreed timeline, hosts and emails
        # inside the identifier derivation, brand identifiers from the allowed set,
        # and the timeline role marks present in the artefacts that own them.
        for match in DATE_RE.finditer(bodies):
            value = int(match.group(1)) * 12 + int(match.group(2))
            if not TIMELINE_MIN <= value <= TIMELINE_MAX:
                errors.append(f"{label}: date outside the agreed timeline: {match.group(0)}")
        for match in HOST_RE.finditer(bodies):
            host = match.group(1).lower()
            if not (
                host == "homerdrive.invalid"
                or host.endswith(".homerdrive.invalid")
                or SHIPPER_HOST_RE.fullmatch(host)
            ):
                errors.append(f"{label}: host outside the identifier derivation: {host}")
        for match in EMAIL_RE.finditer(bodies):
            local, domain = match.group(1).lower(), match.group(2).lower()
            if domain == "homerdrive.invalid" and local not in STAFF_LOCALS:
                errors.append(f"{label}: email outside the staff roster: {match.group(0)}")
            elif SHIPPER_HOST_RE.fullmatch(domain) is None and domain != "homerdrive.invalid" \
                    and not domain.endswith(".homerdrive.invalid"):
                errors.append(f"{label}: email outside the derivation: {match.group(0)}")
        for match in BRAND_TOKEN_RE.finditer(bodies):
            if match.group(1) not in ALLOWED_BRAND_TOKENS:
                errors.append(f"{label}: unknown brand identifier: {match.group(1)}")
        for role_id, marks in REQUIRED_TIMELINE_MARKS.items():
            if item_id == role_id:
                enhanced = getattr(item, "enhanced", "")
                for mark in marks:
                    if mark not in enhanced:
                        errors.append(f"{label}: missing timeline mark {mark}")
        if getattr(item, "category", "") == "credentials":
            enhanced = getattr(item, "enhanced", "").lower()
            if not any(marker in enhanced for marker in SAFE_CREDENTIAL_MARKERS):
                errors.append(f"{label}: credential artefact lacks an inert safety marker")
    return errors


def assert_valid_decoys(decoys: Sequence[Any]) -> None:
    errors = validate_decoys(decoys)
    if errors:
        raise ValueError("invalid decoy catalogue:\n- " + "\n- ".join(errors))
