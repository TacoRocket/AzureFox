from __future__ import annotations

from azurefox.correlation.findings import (
    build_identity_findings,
    build_storage_findings,
    build_vm_findings,
)


def test_build_identity_findings_detects_privileged_identity() -> None:
    findings = build_identity_findings(
        [
            {
                "id": "id-1",
                "name": "ua-app",
                "identity_type": "userAssigned",
                "principal_id": "p-1",
            }
        ],
        [
            {
                "id": "ra-1",
                "scope_id": "/subscriptions/s1",
                "principal_id": "p-1",
                "role_name": "Owner",
            }
        ],
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_build_storage_findings_public_and_allow() -> None:
    findings = build_storage_findings(
        [
            {
                "id": "st-1",
                "name": "stpub",
                "public_access": True,
                "network_default_action": "Allow",
            }
        ]
    )
    assert len(findings) == 2


def test_build_vm_findings_public_with_identity() -> None:
    findings = build_vm_findings(
        [
            {
                "id": "vm-1",
                "name": "vm-web",
                "public_ips": ["1.2.3.4"],
                "identity_ids": ["id-1"],
            }
        ]
    )
    assert len(findings) == 1
