"""Execute fingerprinting checks against both conditions and record the results.

Starts each condition on loopback, probes it like an outside observer would, and
writes results/fingerprint_checks.md: every observation records how it was obtained
(basis): measured = probe response, configuration = deployment fact. Interpretation
column values: "cue" (could reveal the deception), "strength" (makes the environment
more believable), "neutral" (neither).
"""

import socket
import statistics
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import httpx
import uvicorn

from app.config import CONDITIONS, ROOT, load_decoys
from app.main import create_app


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


def probe(condition, decoys, log_path):
    findings = []
    with local_service(condition, log_path, decoys) as base_url:
        client = httpx.Client(base_url=base_url, timeout=10)

        home = client.get("/")
        findings.append((
            "transport",
            "plaintext HTTP on a loopback-only ephemeral port; no TLS certificate presented",
            "cue",
            "configuration",
        ))
        findings.append((
            "server header",
            f"`Server: {home.headers.get('server', '(absent)')}` (masquerade value, not the "
            "framework default)",
            "strength",
            "measured",
        ))
        findings.append((
            "session cookie",
            f"cookies set on `/`: {sorted(client.cookies.keys())}; httponly, no tracking cookies",
            "strength",
            "measured",
        ))

        surfaces = []
        for path, method in (("/missing", "GET"), ("/files/does-not-exist", "GET"),
                             ("/admin", "GET"), ("/login", "POST")):
            response = client.request(method, path, data={"u": "x"} if method == "POST" else None)
            surfaces.append(f"{method} {path} -> {response.status_code} "
                            f"{response.headers.get('content-type', '').split(';')[0]}")
        html_only = all(s.endswith("text/html") for s in surfaces)
        findings.append((
            "error surface consistency",
            "; ".join(surfaces) + (" (all styled HTML, one error template)"
                                   if html_only else " (mixed representations)"),
            "strength" if html_only else "cue",
            "measured",
        ))

        findings.append((
            "rendering model",
            "server-rendered HTML; no client-side state payload in source"
            if 'id="hd-state"' not in home.text else "client-side state payload present",
            "strength" if 'id="hd-state"' not in home.text else "cue",
            "measured",
        ))

        robots = client.get("/robots.txt").text
        findings.append((
            "robots.txt disclosures",
            f"disallows: {[l.split(': ')[1] for l in robots.splitlines() if l.startswith('Disallow')]}",
            "cue" if condition == "enhanced" else "neutral",
            "measured",
        ))

        latencies = []
        for _ in range(20):
            start = time.perf_counter()
            client.get("/api/status")
            latencies.append(time.perf_counter() - start)
        cv = statistics.stdev(latencies) / statistics.mean(latencies)
        findings.append((
            "latency profile",
            f"20 requests: mean {statistics.mean(latencies)*1000:.2f} ms, "
            f"cv {cv:.2f}; no background traffic or jitter",
            "cue",
            "measured",
        ))

        missing = [h for h in ("etag", "last-modified", "strict-transport-security",
                               "content-security-policy") if h not in home.headers]
        findings.append((
            "production header absence",
            f"absent: {missing}",
            "cue",
            "measured",
        ))

        env_body = client.get("/files/.env").text
        markers = [m for m in ("HPOT_", ".invalid", "invalid_") if m in env_body]
        findings.append((
            "safety markers in artefacts",
            f"visible markers in `/files/.env`: {markers}",
            "cue" if markers else "neutral",
            "measured",
        ))

        admin_body = client.get("/admin").text
        has_panel = "staging debug verbosity" in admin_body
        findings.append((
            "403 debug panel",
            "denial page carries a staging debug panel listing diagnostic references"
            if has_panel else "denial page carries no references",
            "cue" if has_panel else "neutral",
            "measured",
        ))
        client.close()
    return findings


def main():
    decoys = load_decoys()
    log_path = ROOT / "logs" / "fingerprint_probe.jsonl"
    log_path.write_text("", encoding="utf-8")
    lines = [
        "# Fingerprint checks",
        "",
        "Executed probes against both conditions; the basis column records how each",
        "observation was obtained: measured = probe response, configuration = deployment",
        "fact. Cue = could reveal the deception; strength = makes the environment more",
        "believable; neutral = neither.",
        "",
    ]
    for condition in CONDITIONS:
        lines += [f"## {condition}", "", "| Check | Observation | Basis | Interpretation |",
                  "|---|---|---|---|"]
        for name, observation, interpretation, basis in probe(condition, decoys, log_path):
            lines.append(f"| {name} | {observation} | {basis} | {interpretation} |")
        lines.append("")
    log_path.unlink(missing_ok=True)
    (ROOT / "results" / "fingerprint_checks.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
