from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from azurefox.models.common import OutputMode


@dataclass(slots=True)
class GlobalOptions:
    tenant: str | None
    subscription: str | None
    output: OutputMode
    outdir: Path
    debug: bool

    @property
    def loot_dir(self) -> Path:
        return self.outdir / "loot"
