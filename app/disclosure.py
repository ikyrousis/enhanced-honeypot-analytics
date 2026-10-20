"""Reference-disclosure scanning shared by the portal, the runner and analysis."""

import re

FILE_REF_RE = re.compile(r"/files/[A-Za-z0-9._/-]+")
LITERAL_REF_RES = {
    "/api/users": re.compile(r"/api/users(?![A-Za-z0-9_/-])"),
    "/login": re.compile(r"/login(?![A-Za-z0-9_/-])"),
}


def scan_refs(text: str) -> set[str]:
    """References a response body discloses to the reader.

    Pages are server-rendered; chrome stays out of the scan by construction because
    templates use relative form actions and carry no navigation links.
    """
    refs = {ref.rstrip(".,;:") for ref in FILE_REF_RE.findall(text)}
    refs.update(lit for lit, rx in LITERAL_REF_RES.items() if rx.search(text))
    return refs
