from __future__ import annotations

from pathlib import Path

import pytest

from azurefox.collectors.provider import FixtureProvider
from azurefox.config import GlobalOptions
from azurefox.models.common import OutputMode, RoleTrustsMode


@pytest.fixture()
def fixture_dir() -> Path:
    return Path(__file__).resolve().parent / "fixtures" / "lab_tenant"


@pytest.fixture()
def fixture_provider(fixture_dir: Path) -> FixtureProvider:
    return FixtureProvider(fixture_dir)


@pytest.fixture()
def options(tmp_path: Path) -> GlobalOptions:
    return GlobalOptions(
        tenant="11111111-1111-1111-1111-111111111111",
        subscription="22222222-2222-2222-2222-222222222222",
        output=OutputMode.JSON,
        outdir=tmp_path,
        debug=False,
        role_trusts_mode=RoleTrustsMode.FAST,
    )
