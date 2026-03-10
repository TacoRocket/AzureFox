from __future__ import annotations

import json
import os

import pytest
from typer.testing import CliRunner

from azurefox.cli import app

pytestmark = pytest.mark.integration


@pytest.mark.skipif(
    os.getenv("AZUREFOX_RUN_INTEGRATION") != "1",
    reason="Set AZUREFOX_RUN_INTEGRATION=1 to execute integration tests.",
)
def test_whoami_integration_smoke() -> None:
    subscription = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription:
        pytest.skip("AZURE_SUBSCRIPTION_ID not set")

    runner = CliRunner()
    result = runner.invoke(app, ["--subscription", subscription, "--output", "json", "whoami"])
    assert result.exit_code == 0

    payload = json.loads(result.stdout)
    assert payload["metadata"]["command"] == "whoami"
    assert payload["subscription"]["id"]
