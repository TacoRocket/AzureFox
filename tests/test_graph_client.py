from __future__ import annotations

from types import SimpleNamespace

from azurefox.clients.graph import GraphBatchRequest, GraphClient
from azurefox.errors import ErrorKind


def test_graph_batch_execute_preserves_status_aware_error_kinds(monkeypatch) -> None:
    client = GraphClient(SimpleNamespace())

    def _fake_post(self, _url: str, _payload: dict) -> dict:
        return {
            "responses": [
                {
                    "id": "0",
                    "status": 401,
                    "body": {
                        "error": {
                            "code": "InvalidAuthenticationToken",
                            "message": "Access token is invalid",
                        }
                    },
                },
                {
                    "id": "1",
                    "status": 403,
                    "body": {
                        "error": {
                            "code": "Authorization_RequestDenied",
                            "message": "Forbidden",
                        }
                    },
                },
                {
                    "id": "2",
                    "status": 429,
                    "body": {
                        "error": {
                            "code": "TooManyRequests",
                            "message": "Rate limit exceeded",
                        }
                    },
                },
            ]
        }

    monkeypatch.setattr(GraphClient, "_post", _fake_post)

    _results, errors = client.batch_get_objects_by_key(
        [
            GraphBatchRequest(key="auth", path="/applications/app-a"),
            GraphBatchRequest(key="forbidden", path="/servicePrincipals/sp-a"),
            GraphBatchRequest(key="throttle", path="/servicePrincipals/sp-b"),
        ]
    )

    assert errors["auth"].kind == ErrorKind.AUTH_FAILURE
    assert errors["forbidden"].kind == ErrorKind.PERMISSION_DENIED
    assert errors["throttle"].kind == ErrorKind.THROTTLING
