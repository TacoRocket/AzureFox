# databases API Mapping

## Slice Goal

Surface Azure SQL server endpoint, network posture, identity context, and visible database
inventory before broader multi-engine depth exists.

This first version answers:
"Which Azure SQL servers expose the most interesting endpoint, network posture, and visible user
database inventory for operator follow-up?"

## Initial Scope

- Azure SQL server enumeration
- Fully qualified server endpoint visibility
- Public network access and minimal TLS posture
- Managed identity context
- Visible user-database inventory per server

## Explicit Non-Goals For V1

- PostgreSQL or MySQL flexible-server coverage
- Database content analysis
- Firewall-rule, auditing, or threat-detection depth

## Primary APIs

- `azure.mgmt.sql.SqlManagementClient.servers.list`
- `azure.mgmt.sql.SqlManagementClient.databases.list_by_server`

## Correlation / Joins

- Join server posture with visible user-database inventory into one operator-first server row
- Keep the first slice Azure SQL-first rather than broadening into multi-engine normalization

## Blind Spots

- Visible database names do not prove query access
- Missing database inventory can reflect partial-read limits on child enumeration

