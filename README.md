sqlserver-login-audit
=====================

A DBMaster plugin that parses native sql server logs to get aggregated logon statistics


Parameters
==========

Parameter | Description | Required
----|------|----
Servers | List of connections to pull logs from. When empty - all servers will be used  | no

Result
==========

Column | Description
----|------|----
Server | DBMaster connection name
Principal | Windows or sql principal name
Source | IP address (if principal tried to logon from different ip addresses table will have multiple lines)
Last Success Time | Last time principal was able to logon successfully
Last Failed Time | Last time principal had a failed attempt to logon
# of Logins | Total number of attempts to logon by the principal
