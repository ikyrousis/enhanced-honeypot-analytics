"""Check session conformance and write three behavioural measures to CSV."""

import csv
import json
from collections import defaultdict
from datetime import datetime
from statistics import mean

from jsonschema import Draft202012Validator, FormatChecker

from app.config import CONDITIONS, REPETITIONS, ROOT, load_decoys, load_playbooks
from app.intent import classify_intent
from app.policy import FOLLOW_BUDGET, next_follow

MEASURES = (
    "interaction_count",
    "artefacts_touched",
    "follow_through_count",
    "distinct_references_shown",
    "cascade_depth",
)


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def analyze():
    validator = Draft202012Validator(
        json.loads((ROOT / "data" / "event.schema.json").read_text(encoding="utf-8")),
        format_checker=FormatChecker(),
    )
    decoys = {f"/files/{item.path}": item for item in load_decoys()}
    playbooks = {item["id"]: item for item in load_playbooks()}
    expected_sessions = {
        f"{condition}-{playbook}-{repeat:02d}": (condition, playbook)
        for condition in CONDITIONS for playbook in playbooks for repeat in REPETITIONS
    }
    groups = defaultdict(list)
    event_count = 0
    for line in (ROOT / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        validator.validate(event)
        if event["playbook_id"] not in playbooks:
            raise ValueError("An event names an unknown playbook")
        artefact = decoys.get(event["path"]) if (
            event["method"] == "GET" and event["status_code"] == 200
        ) else None
        expected_artefact = (artefact.id, artefact.category) if artefact else (None, None)
        if (event["artefact_id"], event["artefact_category"]) != expected_artefact:
            raise ValueError("An event has inconsistent artefact metadata")
        if set(event["intent_labels"]) != set(classify_intent(
            event["method"], event["path"], event["artefact_category"],
        )):
            raise ValueError("An event has labels inconsistent with the observed action")
        groups[event["session_id"]].append(event)
        event_count += 1
    if len(groups) < 15:
        raise ValueError("The assignment requires at least 15 executed sessions")
    if set(groups) != set(expected_sessions):
        missing = sorted(set(expected_sessions) - set(groups))
        unexpected = sorted(set(groups) - set(expected_sessions))
        raise ValueError(f"Unmatched session matrix: missing={missing}, unexpected={unexpected}")
    rows = []
    server_sessions = {}
    for session_id, events in sorted(groups.items()):
        if len({(e["condition"], e["playbook_id"]) for e in events}) != 1:
            raise ValueError(f"Mixed conditions or playbooks in {session_id}")
        events.sort(key=lambda event: event["sequence"])
        if [e["sequence"] for e in events] != list(range(1, len(events) + 1)):
            raise ValueError(f"Missing or repeated sequence numbers in {session_id}")
        cookies = {e["server_session"] for e in events}
        if len(cookies) != 1:
            raise ValueError(f"Multiple server sessions inside {session_id}")
        server_sessions[session_id] = cookies.pop()
        times = [datetime.fromisoformat(e["timestamp"]) for e in events]
        if times != sorted(times):
            raise ValueError(f"Timestamps are out of order in {session_id}")
        first = events[0]
        if (first["condition"], first["playbook_id"]) != expected_sessions[session_id]:
            raise ValueError(f"Session identifier disagrees with its metadata in {session_id}")
        playbook = playbooks[first["playbook_id"]]
        core = playbook["steps"]
        core_events = events[:len(core)]
        actual_core = [(e["method"], e["path"], tuple(sorted(e["query_keys"]))) for e in core_events]
        expected_core = [(s["method"], s["path"], tuple(sorted(s.get("params", {})))) for s in core]
        if any(e["follow_through"] for e in core_events) or actual_core != expected_core:
            raise ValueError(f"An incomplete or changed core playbook in {session_id}")
        # Replay the disclosure chain and the condition-agnostic exploration policy
        # in one pass: what each request could already have seen, what each response
        # added, and whether every follow step is exactly the policy's next pick.
        accum: set[str] = set()
        order: list[str] = []
        requested: set[str] = set()
        depth_of_ref: dict[str, int] = {}
        follows = 0
        cascade_depth = 0
        for index, event in enumerate(events):
            if sorted(accum) != event["disclosed_before"]:
                raise ValueError(f"Disclosure chain broken in {session_id}")
            depth = 0
            if index >= len(core):
                expected = next_follow(order, requested)
                if (
                    not event["follow_through"]
                    or event["path"] != expected
                    or follows >= FOLLOW_BUDGET
                ):
                    raise ValueError(
                        f"A follow step deviates from the exploration policy in {session_id}"
                    )
                follows += 1
                depth = depth_of_ref.get(event["path"], 1)
                cascade_depth = max(cascade_depth, depth)
            elif event["follow_through"]:
                raise ValueError(f"A core step is flagged as follow-through in {session_id}")
            if event["follow_through"] and event["path"] not in event["disclosed_before"]:
                raise ValueError(
                    f"Follow flag without prior server-observed disclosure in {session_id}"
                )
            for ref in event["disclosed_here"]:
                if ref not in order:
                    order.append(ref)
                    depth_of_ref[ref] = depth + 1
            accum.update(event["disclosed_here"])
            requested.add(event["path"])
        if follows < FOLLOW_BUDGET and next_follow(order, requested) is not None:
            raise ValueError(
                f"Session stopped following although references remained in {session_id}"
            )
        if len(set(server_sessions.values())) != len(server_sessions):
            raise ValueError("A server session cookie is shared between claimed sessions")
        rows.append({
            "session_id": session_id,
            "condition": first["condition"],
            "playbook_id": first["playbook_id"],
            "interaction_count": len(events),
            "artefacts_touched": len({e["artefact_id"] for e in events if e["artefact_id"]}),
            "follow_through_count": sum(e["follow_through"] for e in events),
            "distinct_references_shown": len(order),
            "cascade_depth": cascade_depth,
            "cluster": (
                "no-reference-engagement" if follows == 0
                else "deep-cascade" if cascade_depth >= 3
                else "bounded-hops"
            ),
            "intent_labels": "|".join(sorted({label for e in events for label in e["intent_labels"]})),
        })
    summaries = []
    for condition in CONDITIONS:
        selected = [row for row in rows if row["condition"] == condition]
        summaries.append({
            "condition": condition,
            "sessions": len(selected),
            **{f"mean_{measure}": round(mean(row[measure] for row in selected), 4)
               for measure in MEASURES},
        })
    # Manual-versus-LLM contribution: attribute every disclosure edge and every
    # policy follow trigger to the provenance of the response that disclosed it.
    llm_curated = {item.id: item.llm_curated for item in load_decoys()}

    def provenance_of(event):
        artefact = event["artefact_id"]
        if artefact is None:
            return "route"
        return "llm_generated" if llm_curated.get(artefact) else "manual"

    edges = defaultdict(int)
    triggers = defaultdict(int)
    for session_id, events in groups.items():
        if events[0]["condition"] != "enhanced":
            continue
        events.sort(key=lambda event: event["sequence"])
        first_discloser: dict[str, str] = {}
        for event in events:
            source = provenance_of(event)
            for ref in event["disclosed_here"]:
                edges[source] += 1
                first_discloser.setdefault(ref, source)
            if event["follow_through"]:
                triggers[first_discloser.get(event["path"], "route")] += 1
    provenance_rows = [
        {
            "provenance": provenance,
            "disclosure_edges": edges[provenance],
            "follow_triggers": triggers[provenance],
        }
        for provenance in ("llm_generated", "manual", "route")
    ]
    write_csv(ROOT / "results" / "provenance_contribution.csv", provenance_rows)
    # Compare matched repetitions without treating deterministic replays as independent attackers.
    by_session = {row["session_id"]: row for row in rows}
    deltas = [
        {
            measure: by_session[f"enhanced-{playbook}-{repeat:02d}"][measure]
            - by_session[f"baseline-{playbook}-{repeat:02d}"][measure]
            for measure in MEASURES
        }
        for playbook in playbooks for repeat in REPETITIONS
    ]
    write_csv(ROOT / "results" / "session_metrics.csv", rows)
    write_csv(ROOT / "results" / "condition_summary.csv", summaries)
    return {
        "events": event_count,
        "sessions": len(rows),
        "conditions": summaries,
        "provenance_contribution": provenance_rows,
        "comparison": {
            "paired_sessions": len(deltas),
            "mean_deltas": {
                measure: round(mean(delta[measure] for delta in deltas), 4)
                for measure in MEASURES
            },
        },
    }


if __name__ == "__main__":
    print(json.dumps(analyze(), indent=2))
