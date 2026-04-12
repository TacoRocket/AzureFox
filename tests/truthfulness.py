from __future__ import annotations

from collections.abc import Sequence


def _field_value(row: object, field: str) -> object:
    if isinstance(row, dict):
        return row.get(field)
    return getattr(row, field, None)


def _duplicate_field_values(rows: Sequence[object], field: str) -> list[object]:
    seen: set[object] = set()
    duplicates: list[object] = []
    for row in rows:
        value = _field_value(row, field)
        if value is None:
            continue
        if value in seen and value not in duplicates:
            duplicates.append(value)
            continue
        seen.add(value)
    return duplicates


def row_by_field(rows: Sequence[object], *, field: str, expected: object) -> object:
    matches = [row for row in rows if _field_value(row, field) == expected]
    if len(matches) != 1:
        raise AssertionError(f"Expected one row with {field}={expected!r}, found {len(matches)}.")
    return matches[0]


def assert_rows_include(rows: Sequence[object], *, field: str, expected: Sequence[object]) -> None:
    duplicates = _duplicate_field_values(rows, field)
    if duplicates:
        raise AssertionError(
            f"Expected unique {field} values, but found duplicates {duplicates!r}."
        )
    actual = {_field_value(row, field) for row in rows}
    missing = [value for value in expected if value not in actual]
    if missing:
        raise AssertionError(
            f"Expected rows with {field} values {missing!r}, "
            f"but actual values were {sorted(actual)!r}."
        )


def assert_rows_exclude(rows: Sequence[object], *, field: str, expected: Sequence[object]) -> None:
    duplicates = _duplicate_field_values(rows, field)
    if duplicates:
        raise AssertionError(
            f"Expected unique {field} values, but found duplicates {duplicates!r}."
        )
    actual = {_field_value(row, field) for row in rows}
    unexpected = [value for value in expected if value in actual]
    if unexpected:
        raise AssertionError(
            f"Expected rows to exclude {unexpected!r}, but actual values were {sorted(actual)!r}."
        )


def assert_issue_collectors_include(
    issues: Sequence[object],
    *,
    expected_collectors: Sequence[str],
) -> None:
    collectors: set[str] = set()
    for issue in issues:
        context = (
            issue.get("context") if isinstance(issue, dict) else getattr(issue, "context", None)
        )
        if isinstance(context, dict):
            collector = context.get("collector")
            if collector:
                collectors.add(str(collector))

    missing = [collector for collector in expected_collectors if collector not in collectors]
    if missing:
        raise AssertionError(
            f"Expected issue collectors {missing!r}, "
            f"but actual collectors were {sorted(collectors)!r}."
        )
