"""Deploy both conditions on loopback, execute playbooks, and capture responses."""

import asyncio
import json
import socket
import threading
import time
from contextlib import contextmanager

import httpx
import uvicorn

from app.config import CONDITIONS, REPETITIONS, ROOT, load_decoys, load_playbooks
from app.disclosure import scan_refs
from app.main import create_app
from app.policy import FOLLOW_BUDGET, next_follow

CAPTURED_SESSIONS = {
    "baseline-broad_recon-01",
    "enhanced-credential_hunter-01",
    "enhanced-admin_login-01",
}


@contextmanager
def local_service(condition, log_path, decoys):
    with socket.socket() as bound_socket:
        bound_socket.bind(("127.0.0.1", 0))
        port = bound_socket.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            create_app(condition, log_path, decoys),
            host="127.0.0.1", port=port, log_level="error", access_log=False,
            server_header=False,
        ))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [bound_socket]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                if not thread.is_alive() or time.monotonic() >= deadline:
                    raise RuntimeError("Loopback service did not start")
                time.sleep(0.01)
            yield f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            if thread.is_alive():
                raise RuntimeError("Loopback service did not stop")


def fence_language(content_type: str) -> str:
    if "json" in content_type:
        return "json"
    if "html" in content_type:
        return "html"
    return "text"


def write_session_capture(session_id: str, condition: str, playbook_id: str, records: list) -> None:
    """Write one Markdown capture file: full response bodies for a complete session.

    Sequence numbers match the `sequence` field of the same session's events in
    logs/events.jsonl, so captures and structured log cross-reference exactly.
    """
    lines = [
        f"# Session {session_id}",
        "",
        f"Condition: {condition}  ",
        f"Playbook: {playbook_id}  ",
        f"Requests: {len(records)} (sequences 1-{len(records)} in `logs/events.jsonl`)  ",
        "Response bodies are verbatim; request metadata lives in the structured log.",
        "",
    ]
    for index, record in enumerate(records, start=1):
        lines += [
            f"## {index}. {record['method']} {record['path']} -> HTTP {record['status']}",
            "",
            f"- Followed observed reference: {'yes' if record['follow'] else 'no'}",
            f"- Content-Type: {record['content_type']}",
            "",
            f"```{fence_language(record['content_type'])}",
            record["body"].rstrip("\n"),
            "```",
            "",
        ]
    (ROOT / "captures" / f"{session_id}.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )


def write_capture_index(summaries: list) -> None:
    lines = [
        "# Captured responses",
        "",
        "Complete verbatim response captures for three laboratory sessions, one file per",
        "session. Request metadata for every session, including these, is in",
        "`../logs/events.jsonl`; the numbered sections in each file match that session's",
        "`sequence` values.",
        "",
        "| Session | Condition | Playbook | Requests |",
        "|---|---|---|---|",
    ]
    for summary in summaries:
        lines.append(
            f"| [{summary['session_id']}]({summary['session_id']}.md) "
            f"| {summary['condition']} | {summary['playbook_id']} | {summary['requests']} |"
        )
    lines.append("")
    (ROOT / "captures" / "index.md").write_text("\n".join(lines), encoding="utf-8")


async def execute_condition(base_url, condition, playbooks):
    """Run each playbook's core steps, then the condition-agnostic follow policy.

    Each session gets its own HTTP client so the server-minted session cookie
    stays isolated. After the core steps, the session follows at most
    FOLLOW_BUDGET references, chosen in first-observation order among the
    references its own responses disclosed and it has not requested yet. The
    policy is identical in both conditions and knows nothing about either
    condition's content.
    """
    sessions = 0
    requests = 0
    capture_summaries = []
    for playbook in playbooks:
        for repetition in REPETITIONS:
            session_id = f"{condition}-{playbook['id']}-{repetition:02d}"
            observed_order: list[str] = []
            requested: set[str] = set()
            records = []

            def note_refs(body: str) -> None:
                for ref in sorted(scan_refs(body)):
                    if ref not in observed_order:
                        observed_order.append(ref)

            async with httpx.AsyncClient(
                base_url=base_url, timeout=10, follow_redirects=False, trust_env=False,
            ) as client:

                async def request_step(step, follow=False):
                    nonlocal requests
                    path = step["path"]
                    if not path.startswith("/") or path.startswith("//"):
                        raise ValueError("Playbook paths must stay on the loopback service")
                    headers = {
                        "X-Lab-Session": session_id,
                        "X-Lab-Playbook": playbook["id"],
                        "X-Lab-Follow": "1" if follow else "0",
                    }
                    response = await client.request(
                        step["method"], path, headers=headers,
                        params=step.get("params"), data=step.get("form"),
                    )
                    if response.status_code >= 500:
                        raise RuntimeError(f"Service error in {session_id}: {path}")
                    requests += 1
                    records.append({
                        "method": step["method"],
                        "path": path,
                        "status": response.status_code,
                        "follow": follow,
                        "content_type": response.headers.get("content-type", ""),
                        "body": response.text,
                    })
                    return response.text

                for step in playbook["steps"]:
                    note_refs(await request_step(step))
                    requested.add(step["path"])
                follows = 0
                while follows < FOLLOW_BUDGET:
                    nxt = next_follow(observed_order, requested)
                    if nxt is None:
                        break
                    note_refs(await request_step({"method": "GET", "path": nxt}, follow=True))
                    requested.add(nxt)
                    follows += 1
            if session_id in CAPTURED_SESSIONS:
                write_session_capture(session_id, condition, playbook["id"], records)
                capture_summaries.append({
                    "session_id": session_id,
                    "condition": condition,
                    "playbook_id": playbook["id"],
                    "requests": len(records),
                })
            sessions += 1
    return {
        "condition": condition,
        "sessions": sessions,
        "requests": requests,
        "captures": capture_summaries,
    }


def main():
    # Prepare one catalogue and one protocol for both conditions before any run.
    decoys = load_decoys()
    playbooks = load_playbooks()
    log_path = ROOT / "logs" / "events.jsonl"
    captures_dir = ROOT / "captures"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    captures_dir.mkdir(parents=True, exist_ok=True)
    for stale in list(captures_dir.glob("*.md")) + [captures_dir / "interactions.txt"]:
        stale.unlink(missing_ok=True)
    for name in ("session_metrics.csv", "condition_summary.csv"):
        (ROOT / "results" / name).unlink(missing_ok=True)
    log_path.write_text("", encoding="utf-8")
    results = []
    capture_summaries = []
    for condition in CONDITIONS:
        with local_service(condition, log_path, decoys) as base_url:
            outcome = asyncio.run(execute_condition(base_url, condition, playbooks))
            capture_summaries.extend(outcome.pop("captures"))
            results.append(outcome)
    captured_ids = {summary["session_id"] for summary in capture_summaries}
    if captured_ids != CAPTURED_SESSIONS:
        raise RuntimeError(
            f"Configured capture sessions missing from this run: "
            f"{sorted(CAPTURED_SESSIONS - captured_ids)}"
        )
    write_capture_index(capture_summaries)
    print(json.dumps({
        "validated_decoys": len(decoys),
        "validated_categories": len({item.category for item in decoys}),
        "recorded_llm_curated": sum(item.llm_curated for item in decoys),
        "validated_playbooks": len(playbooks),
        "repetitions_per_condition": len(REPETITIONS),
        "planned_sessions": len(CONDITIONS) * len(REPETITIONS) * len(playbooks),
        "follow_budget": FOLLOW_BUDGET,
        "runs": results,
    }, indent=2))


if __name__ == "__main__":
    main()
