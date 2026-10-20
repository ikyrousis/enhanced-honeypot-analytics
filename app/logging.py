"""Schema-validated JSONL capture with no identifying or credential fields."""

import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from app.config import ROOT


class EventWriter:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        schema = json.loads((ROOT / "data" / "event.schema.json").read_text(encoding="utf-8"))
        self.validator = Draft202012Validator(schema, format_checker=FormatChecker())

    def write(self, event: dict) -> None:
        self.validator.validate(event)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")
