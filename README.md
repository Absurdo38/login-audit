sqlserver-login-audit
=========================

A DBMaster plugin that parses native sql server logs to get aggregated logon statistics

## Parameters

Parameter | Description | Required
----|------|----
Servers | List of connections to pull logs from. When empty - all servers will be used  | no

## Security

sysadmin role is required on each server to use this tool

## Results

Result will contain a list of principals found in sql server
* Principals can be deleted by this time (in this case resulting table will have a row with empty source and total logon attempts equal to zero)
* Principals are not found in event log (principal name will include *deleted* indicator)

Column | Description
----|------|----
Server | DBMaster connection name
Principal | Windows or sql principal name
Source | IP address (if principal tried to logon from different ip addresses table will have multiple lines)
Last Success Time | Last time principal was able to logon successfully
Last Failed Time | Last time principal had a failed attempt to logon
Total Logon Attempts | Total number of attempts to logon by the principal (both successfull and failed)
