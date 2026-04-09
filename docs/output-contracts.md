# Output Contracts

Each command output is represented by a versioned Pydantic model and is rendered into table/JSON/CSV from the same model instance.

AzureFox also writes a `loot/` artifact for each command, but `loot` is not the same thing as the
full JSON contract.

## Schema Version

- Current: `1.3.0`

## Contract Rules

- JSON output is deterministic (`sort_keys=True` serialization).
- JSON output is the full structured command contract and authoritative backing record.
- `loot` is the smaller operator-facing handoff for fast follow-up and later chain-oriented
  workflows.
- `loot` should focus on the top-ranked high-value targets from a command, rather than mirror the
  full JSON record.
- `loot` may omit context-only metadata, omit empty informational sections, and cap the primary
  target list to the top-ranked rows while JSON keeps the full list.
- Table output must not contain fields that are absent from the JSON contract.
- Each command schema is stored under `schemas/<command>.schema.json`.
- Fixture snapshots under `tests/golden/` are regression baselines.

## Milestone 1 Models

- `WhoAmIOutput`
- `InventoryOutput`
- `RbacOutput`
- `PrincipalsOutput`
- `PermissionsOutput`
- `PrivescOutput`
- `RoleTrustsOutput`
- `AuthPoliciesOutput`
- `ManagedIdentitiesOutput`
- `StorageOutput`
- `VmsOutput`
