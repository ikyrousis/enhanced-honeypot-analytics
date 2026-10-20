"""Load the committed decoy catalogue and playbook definitions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONDITIONS = ("baseline", "enhanced")
REPETITIONS = (1, 2)
LAB_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")


@dataclass(frozen=True)
class Decoy:
    id: str
    category: str
    path: str
    media_type: str
    llm_curated: bool
    prompt: str
    provenance: str
    manual_curation_notes: str
    baseline: str
    enhanced: str

    def content(self, condition: str) -> str:
        return self.enhanced if condition == "enhanced" else self.baseline


def load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = yaml.safe_load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a YAML mapping")
    return value


def load_decoys() -> list[Decoy]:
    payload = load_yaml(ROOT / "data" / "decoys.yaml")
    rows = payload.get("decoys", [])
    decoys = [Decoy(**row) for row in rows]
    from .decoy_validation import assert_valid_decoys

    assert_valid_decoys(decoys)
    return decoys


def load_playbooks() -> list[dict[str, Any]]:
    """Check the fixed comparison inputs before starting or replacing captures."""
    playbooks = load_yaml(ROOT / "data" / "playbooks.yaml").get("playbooks")
    if not isinstance(playbooks, list) or len(playbooks) < 5:
        raise ValueError("At least five uniquely identified playbooks are required")
    identifiers = set()
    for playbook in playbooks:
        if not isinstance(playbook, dict):
            raise ValueError("Each playbook must be a mapping")
        identifier = playbook.get("id")
        if (
            not isinstance(identifier, str)
            or not LAB_ID.fullmatch(identifier)
            or identifier in identifiers
            or any(not LAB_ID.fullmatch(f"{condition}-{identifier}-{repeat:02d}")
                   for condition in CONDITIONS for repeat in REPETITIONS)
        ):
            raise ValueError("Playbook identifiers must be unique, safe lab identifiers")
        identifiers.add(identifier)
        description = playbook.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ValueError(f"Missing objective for {identifier}")
        core = playbook.get("steps")
        if not isinstance(core, list) or not core:
            raise ValueError(f"Invalid core steps for {identifier}")
        for step in core:
            if not isinstance(step, dict):
                raise ValueError(f"Invalid request step for {identifier}")
            path = step.get("path")
            if (
                step.get("method") not in {"GET", "POST"}
                or not isinstance(path, str)
                or not path.startswith("/")
                or path.startswith("//")
                or len(path) > 2048
                or "?" in path
                or "#" in path
            ):
                raise ValueError(f"{identifier}: use GET/POST and a local path without query or fragment")
            for field in ("params", "form"):
                values = step.get(field, {})
                if not isinstance(values, dict) or any(
                    not isinstance(key, str) or not key or len(key) > 80 for key in values
                ):
                    raise ValueError(f"{identifier}: {field} must contain bounded string keys")
    return playbooks
