from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from azurefox.models.common import OutputMode, RoleTrustsMode


@dataclass(slots=True)
class GlobalOptions:
    tenant: str | None
    subscription: str | None
    output: OutputMode
    outdir: Path
    debug: bool
    role_trusts_mode: RoleTrustsMode = RoleTrustsMode.FAST

    @property
    def loot_dir(self) -> Path:
        return self.outdir / "loot"

    @property
    def json_dir(self) -> Path:
        return self.outdir / "json"

    @property
    def table_dir(self) -> Path:
        return self.outdir / "table"

    @property
    def csv_dir(self) -> Path:
        return self.outdir / "csv"
