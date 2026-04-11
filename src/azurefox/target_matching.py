from __future__ import annotations

from urllib.parse import urlparse

_TARGET_HOST_SUFFIXES = {
    "app-services": (".azurewebsites.net",),
    "functions": (".azurewebsites.net",),
    "aks": (".azmk8s.io",),
    "arm-deployments": (),
}

_TARGET_RESOURCE_ID_FRAGMENTS = {
    "app-services": ("/providers/microsoft.web/sites/",),
    "functions": ("/providers/microsoft.web/sites/",),
    "aks": ("/providers/microsoft.containerservice/managedclusters/",),
    "arm-deployments": ("/providers/microsoft.resources/deployments/",),
}


def normalize_exact_target_host(value: str, *, target_family: str) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        hostname = (parsed.hostname or parsed.netloc).strip().lower()
        if hostname and _is_canonical_exact_target_host(hostname, target_family=target_family):
            return hostname
        return None
    if "." in text and " " not in text and "/" not in text.strip("/"):
        hostname = text.lower()
        if _is_canonical_exact_target_host(hostname, target_family=target_family):
            return hostname
    return None


def _is_canonical_exact_target_host(hostname: str, *, target_family: str) -> bool:
    allowed_suffixes = _TARGET_HOST_SUFFIXES.get(target_family, ())
    if not any(hostname.endswith(suffix) for suffix in allowed_suffixes):
        return False
    if target_family in {"app-services", "functions"}:
        return hostname.count(".") == 2
    return True


def normalize_exact_target_resource_id(value: str | None, *, target_family: str) -> str | None:
    text = str(value or "").strip()
    if not text.startswith("/subscriptions/"):
        return None
    normalized = text.rstrip("/").lower()
    allowed_fragments = _TARGET_RESOURCE_ID_FRAGMENTS.get(target_family, ())
    if allowed_fragments and not any(fragment in normalized for fragment in allowed_fragments):
        return None
    return normalized


def looks_like_exact_target_value(
    value: str,
    *,
    target_family: str,
    allow_host_or_url: bool,
) -> bool:
    if normalize_exact_target_resource_id(value, target_family=target_family):
        return True
    if not allow_host_or_url:
        return False
    return normalize_exact_target_host(value, target_family=target_family) is not None
