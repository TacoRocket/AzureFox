# databases API Mapping

## Slice Goal

Surface relational database server endpoint, network posture, identity context, and visible
database inventory across Azure SQL, PostgreSQL Flexible, and MySQL Flexible without broadening
into config-dump depth.

This slice answers:
"Which relational database servers expose the most interesting endpoint, network posture, and
visible user-database inventory for operator follow-up?"

## Initial Scope

- Azure SQL server enumeration
- PostgreSQL Flexible Server enumeration
- MySQL Flexible Server enumeration
- Fully qualified server endpoint visibility
- Public network access and minimal TLS posture
- Managed identity context
- Simple HA / delegated-subnet / private-DNS posture where readable
- Visible user-database inventory per server

## Explicit Non-Goals For This Slice

- Database content analysis
- Firewall-rule, auditing, or threat-detection depth
- Engine-specific parameter/config dumps
- NoSQL engines or other non-relational data services
- Serverless database families and other non-server-shaped surfaces

## Primary APIs

- `azure.mgmt.sql.SqlManagementClient.servers.list`
- `azure.mgmt.sql.SqlManagementClient.databases.list_by_server`
- `azure.mgmt.postgresqlflexibleservers.PostgreSQLManagementClient.servers.list_by_subscription`
- `azure.mgmt.postgresqlflexibleservers.PostgreSQLManagementClient.databases.list_by_server`
- `azure.mgmt.mysqlflexibleservers.MySQLManagementClient.servers.list`
- `azure.mgmt.mysqlflexibleservers.MySQLManagementClient.databases.list_by_server`

## Correlation / Joins

- Join server posture with visible user-database inventory into one operator-first server row
- Normalize the row shape enough that Azure SQL, PostgreSQL Flexible, and MySQL Flexible remain
  comparable in one command without pretending the engines are identical

## Blind Spots

- Visible database names do not prove query access
- Missing database inventory can reflect partial-read limits on child enumeration
- Public network posture does not prove reachability without downstream network controls
- Flexible-server HA or private-network cues are prioritization hints, not proof of exploitable
  exposure
