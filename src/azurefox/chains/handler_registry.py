from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, TypeVar

from azurefox.models.chains import ChainPathRecord

StateT = TypeVar("StateT")
SourceT = TypeVar("SourceT")


class ChainFamilyHandler(Protocol[StateT, SourceT]):
    name: str

    def build_records(self, state: StateT, source: SourceT) -> list[ChainPathRecord]:
        ...


def run_chain_handlers(
    handlers: Sequence[ChainFamilyHandler[StateT, SourceT]],
    *,
    state: StateT,
    sources: Iterable[SourceT],
) -> list[ChainPathRecord]:
    records: list[ChainPathRecord] = []
    seen_chain_ids: set[str] = set()

    for source in sources:
        for handler in handlers:
            for record in handler.build_records(state, source):
                if record.chain_id in seen_chain_ids:
                    continue
                seen_chain_ids.add(record.chain_id)
                records.append(record)

    return records
