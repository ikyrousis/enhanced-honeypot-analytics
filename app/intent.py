"""Transparent labels for observed HTTP behaviour."""


def classify_intent(method: str, path: str, category: str | None) -> list[str]:
    labels = []
    if category == "credentials" or (path == "/login" and method == "POST"):
        labels.append("credential_access")
    if path.startswith("/admin"):
        labels.append("privilege_seeking")
    if category is not None or path.startswith("/api/users"):
        labels.append("collection")
    if (
        path in {"/", "/robots.txt", "/api/status"}
        or (path == "/login" and method == "GET")
        or not labels
    ):
        labels.append("reconnaissance")
    return labels
