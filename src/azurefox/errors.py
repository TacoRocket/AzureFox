from __future__ import annotations

from enum import StrEnum


class ErrorKind(StrEnum):
    AUTH_FAILURE = "auth_failure"
    PERMISSION_DENIED = "permission_denied"
    THROTTLING = "throttling"
    PARTIAL_COLLECTION = "partial_collection"
    DEPENDENCY_MISSING = "dependency_missing"
    UNKNOWN = "unknown"


class AzureFoxError(Exception):
    def __init__(
        self,
        kind: ErrorKind,
        message: str,
        *,
        command: str | None = None,
        details: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = kind
        self.command = command
        self.details = details or {}


def classify_exception(exc: Exception) -> ErrorKind:
    message = str(exc).lower()
    if "unauthorized" in message or "authentication" in message or "auth failure" in message:
        return ErrorKind.AUTH_FAILURE
    if "forbidden" in message or "permission" in message:
        return ErrorKind.PERMISSION_DENIED
    if "thrott" in message or "rate" in message:
        return ErrorKind.THROTTLING
    return ErrorKind.UNKNOWN
