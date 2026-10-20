"""Generate raw decoy drafts through any OpenAI-compatible LLM endpoint and archive
them with full provenance.

The provider, key and model are configured in .env / environment (see llm_client.py);
nothing provider-specific exists in this script. Raw model outputs are stored verbatim
under data/generation/raw/<artefact_id>.json together with provider host, model id,
date, prompt and sampling parameters, so that the curated content in data/decoys.yaml
can be audited as a diff against the model draft.

Usage:
    python generate_decoys.py                 # generate any missing raw drafts
    python generate_decoys.py --force         # regenerate everything
    python generate_decoys.py --model <id>    # override the configured model
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from app.config import ROOT
from app.llm_client import LLMClient, load_llm_config
RAW_DIR = ROOT / "data" / "generation" / "raw"

BRAND_RULES = """You are drafting one decoy artefact for a fictional company used in a
security-teaching honeypot lab. Brand facts you MUST follow exactly:
- Company: Maximum Homerdrive, B2B logistics SaaS ("Homerdrive Dispatch"), ~85 staff,
  founded 2016, HQ Rotterdam. This artefact lives in the STAGING environment.
- Domains: only *.invalid (emails first.last@homerdrive.invalid; hosts
  api.internal.homerdrive.invalid, db.internal.homerdrive.invalid,
  git.homerdrive.invalid, registry.internal.homerdrive.invalid).
- Identifiers: AWS profile homerdrive-staging; buckets
  homerdrive-freight-archive-staging and homerdrive-dispatch-backups; services
  dispatch-api, tracking-worker, billing-sync; repo
  git.homerdrive.invalid/dispatch/api-staging.git.
- Staff: a.rivera (platform lead), m.chen (SRE on-call), s.kim (support ops).
- Timeline: 2025-11 tracking cluster decommissioned and bastion key retired;
  2026-02 schema migration to shipment_events; 2026-04 incident note; 2026-07 last
  credential rotation; 2026-10 rotation due.
SAFETY RULES (absolute):
- Everything is invented. No real companies, people, hosts, credentials or personal data.
- Credential-shaped values must be visibly unusable placeholders (e.g. invalid_*,
  HPOT_FAKE_*). No value may be a working secret or match real secret formats
  (no AKIA... keys, no real-shaped JWTs, no valid PEM private keys).
- Never include operational intrusion guidance; narrative references only.
OUTPUT RULES:
- Output ONLY the artefact file content, no explanations, no markdown fences.
- Keep it short and mundane (internal ops voice, not marketing).
- Cross-references to other decoys must use exactly these portal paths when needed:
  /files/.env, /files/.aws/credentials, /files/backups/id_ed25519.old,
  /files/cloud/inventory.json, /files/cloud/task-definition.json,
  /files/backups/customers.sql, /files/database/schema.sql, /files/source/db_client.py,
  /files/source/auth.py, /files/.git/config, /files/runbooks/credential-rotation.txt,
  /files/runbooks/incident-2026-04.txt, /api/users, /login
"""

ARTEFACT_PROMPTS = {
    "env_staging": (
        "Draft a staging .env file for the dispatch-api service. Include APP_ENV, an "
        "unusable API token placeholder, a postgresql DATABASE_URL to "
        "db.internal.homerdrive.invalid with an invalid password placeholder, the AWS "
        "profile name, a support email, and a ROTATION_NOTE line referencing the rotation "
        "runbook portal path."
    ),
    "aws_credentials": (
        "Draft an AWS shared credentials file for the retired homerdrive-staging profile "
        "with impossible key identifiers and invalid placeholders, plus a trailing comment "
        "pointing to the cloud inventory portal path."
    ),
    "cloud_inventory": (
        "Draft a JSON cloud inventory for staging: environment, an impossible account "
        "reference string, region, the two brand buckets, a services array naming "
        "dispatch-api / tracking-worker / billing-sync with .invalid hosts, and a "
        "deployment_manifest field pointing to the task definition portal path."
    ),
    "task_definition": (
        "Draft an ECS-like JSON task definition for dispatch-api: family name, one "
        "container definition with an image on registry.internal.homerdrive.invalid, an "
        "environment entry CONFIG_PATH pointing to the .env portal path, and a secrets "
        "entry whose valueFrom is an invalid parameter reference."
    ),
    "db_backup": (
        "Draft a tiny SQL export header plus a shippers table with exactly three invented "
        "carrier companies (id, company name, contact email at a shipper-*.invalid domain, "
        "placeholder password hashes), and a trailing SQL comment referencing the "
        "db_client.py portal path."
    ),
    "db_client_source": (
        "Draft inert Python source for the dispatch database adapter: a module docstring, "
        "and a describe_connection() function returning a dict with a dsn read from the "
        "DATABASE_URL environment variable defaulting to a comment referencing the .env "
        "portal path, and a schema field referencing the schema.sql portal path. No network "
        "calls, no executable attack code."
    ),
    "auth_source": (
        "Draft inert Python source for the operator authentication adapter: a module "
        "docstring marking it display-only, an authenticate(user, password) function that "
        "always returns False, a DEBUG_AUDIT_PATH constant set to /api/users and a "
        "ROTATION_GUIDE constant referencing the rotation runbook portal path."
    ),
    "credential_rotation": (
        "Draft a plain-text quarterly credential rotation checklist for staging: numbered "
        "steps referencing the .env portal path, the AWS credentials portal path, the "
        "/api/users audit view and the /login operator portal; state last rotation 2026-07 "
        "and next due 2026-10; owner a.rivera, reviewer s.kim."
    ),
    "incident_note": (
        "Draft a plain-text post-incident note dated 2026-04 authored by m.chen: finding "
        "that a retired key-shaped backup remained at the id_ed25519.old portal path after "
        "the 2025-11 tracking cluster decommission; context that repository metadata at the "
        ".git/config portal path referenced an obsolete staging mirror; action to inspect "
        "the cloud inventory portal path and complete the rotation checklist; status closed."
    ),
}


def generate(model: str, force: bool) -> None:
    config = load_llm_config()
    if model:
        config = type(config)(base_url=config.base_url, api_key=config.api_key, model=model)
    client = LLMClient(config)
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    for artefact_id, task in ARTEFACT_PROMPTS.items():
        out = RAW_DIR / f"{artefact_id}.json"
        if out.exists() and not force:
            print(f"skip  {artefact_id} (raw draft exists)")
            continue
        prompt = BRAND_RULES + "\nARTEFACT TASK:\n" + task
        result = client.complete(prompt, temperature=0.7)
        record = {
            "artefact_id": artefact_id,
            "requested_model": config.model,
            "reported_model": result.model,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "temperature": 0.7,
            "prompt": prompt,
            "raw_output": result.text,
            "usage": result.usage,
        }
        out.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")
        cost = (result.usage or {}).get("cost")
        print(f"wrote {artefact_id} ({config.model}, cost={cost})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--model", default="")
    args = parser.parse_args()
    generate(args.model, args.force)
