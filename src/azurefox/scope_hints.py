from __future__ import annotations


def permission_scope_description(
    scope_ids: list[object] | None,
    *,
    scope_count: int | None = None,
) -> str:
    cleaned = _clean_scope_ids(scope_ids)
    if len(cleaned) > 1:
        return f"{len(cleaned)} visible scopes"
    if len(cleaned) == 1:
        return _describe_scope_id(cleaned[0])
    if scope_count and scope_count > 1:
        return f"{scope_count} visible scopes"
    return "visible scope"


def permission_scope_phrase(
    scope_ids: list[object] | None,
    *,
    scope_count: int | None = None,
) -> str:
    cleaned = _clean_scope_ids(scope_ids)
    if len(cleaned) > 1:
        return f"across {len(cleaned)} visible scopes"
    if len(cleaned) == 1:
        scope_description = _describe_scope_id(cleaned[0])
        if scope_description == "subscription-wide scope":
            return f"across {scope_description}"
        return f"on {scope_description}"
    if scope_count and scope_count > 1:
        return f"across {scope_count} visible scopes"
    return "on visible scope"


def _clean_scope_ids(scope_ids: list[object] | None) -> list[str]:
    cleaned: list[str] = []
    for value in scope_ids or []:
        text = str(value or "").strip().rstrip("/")
        if text and text not in cleaned:
            cleaned.append(text)
    return cleaned


def _describe_scope_id(scope_id: str) -> str:
    parts = [part for part in scope_id.split("/") if part]
    lower_parts = [part.lower() for part in parts]

    if len(parts) == 2 and lower_parts[0] == "subscriptions":
        return "subscription-wide scope"

    if "resourcegroups" in lower_parts:
        index = lower_parts.index("resourcegroups")
        if index + 1 < len(parts):
            if len(parts) == index + 2:
                return f"resource group '{parts[index + 1]}'"
            return f"resource '{parts[-1]}'"

    if parts:
        return f"scope '{parts[-1]}'"
    return "visible scope"
