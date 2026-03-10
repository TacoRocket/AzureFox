# Output Contracts

Each command output is represented by a versioned Pydantic model and is rendered into table/JSON/CSV from the same model instance.

## Schema Version

- Current: `1.0.0`

## Contract Rules

- JSON output is deterministic (`sort_keys=True` serialization).
- Table output must not contain fields that are absent from the JSON contract.
- Each command schema is stored under `schemas/<command>.schema.json`.
- Fixture snapshots under `tests/golden/` are regression baselines.

## Milestone 1 Models

- `WhoAmIOutput`
- `InventoryOutput`
- `RbacOutput`
- `ManagedIdentitiesOutput`
- `StorageOutput`
- `VmsOutput`

