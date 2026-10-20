# LLM-Enhanced HTTP Honeypot

Controlled HTTP honeypot experiment: the staging dispatch console of the fictional
Maximum Homerdrive logistics SaaS, probed by six scripted attacker playbooks under two
decoy conditions (sparse `baseline` versus cross-referenced `enhanced`). Runs record
sixteen-field structured events with server-computed disclosure tracking; offline analysis
validates them and computes session measures, behavioural clusters and LLM-versus-manual
provenance attribution. Decoy drafts come from a provider-agnostic LLM step with verbatim
provenance archived alongside the curated corpus. The server-rendered sign-in console
exists for inspection only.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Run

```bash
python -m app.experiment   # execute all playbooks against both conditions on loopback; writes logs/events.jsonl, captures/, results/
python -m app.analysis     # validate the log, replay the disclosure chain and follow policy, compute measures/clusters/provenance; writes results/*.csv
python -m app.fingerprint  # probe both conditions for machine-detectable fingerprinting cues; writes results/fingerprint_checks.md
python -m app.serve        # optional: browse the honeypot at http://127.0.0.1:8000 (inspection only; appends logs/manual-<condition>.jsonl)
python -m app.generate     # optional: regenerate LLM decoy drafts into data/generation/raw/ (needs LLM_* in .env, see .env.example)
```

A run replaces `logs/`, `captures/` and `results/`, copy anything you need first

## Repository map

- `app/` — portal, logging, validation, follow policy, disclosure scan, templates, logo asset, and the entry-point modules above.
- `data/` — decoy catalogue (both conditions, provenance, curation notes), `playbooks.yaml`, event schema, raw model drafts.
- `logs/`, `results/`, `captures/` — generated outputs: event log, CSVs and fingerprint report, verbatim session captures.
