sqlserver-login-audit
=========================

A DBMaster plugin that parses native sql server logs to get aggregated logon statistics

## Parameters

Parameter | Type | Description | Required
----------|:----:|-------------|:----:|
Servers | List | A set of connections to pull logs from. When empty - all servers will be used  | no
Resolve Hosts | Boolean | Will try to resolve hosts by source ip addresses. Enabling host resolution will make the tool to run slower | yes

## Security

sysadmin role is required on each server to use this tool

## Results

Result will contain a list of principals found in sql server per each source. In cases when a user tried to logon from different ip addresses result will have multiple lines - one per each ip.
* Principals can be deleted by this time (in this case resulting table will have a row with empty source and total logon attempts equal to zero)
* Principals are not found in event log (principal name will include *deleted* indicator)

Column | Description
----|------
Server | DBMaster connection name
Principal | SQL Server principal (user) name
Type | Type of sql principal. Values are taken from column type_desc of vsys.server_principals view. Current version supports  SQL_LOGIN and WINDOWS_LOGIN types
Status | Can be one of <ul><li>NOT_IN_LIST - principal was found in log, but wasn't found among server principals. There might be multiple reasons for this status - a principal was deleted; wrong username/password used by a sql client; principal defined via windows groups;and some others <li>NOT_IN_LOG - this is a status when no logon attempts found. This does imply the user is not active - log files cound be deleted recently or server audit is not enabled for the server</li><li>ACTIVE - user was found in log and among server principals</li></ul>
Source | IP address connections were made from
Host | Host name associated with source ip address. This column appears when 'Resolve Hosts' parameter is set to true
Last Success Time | Last time principal was able to logon successfully
Last Failed Time | Last time principal had a failed attempt to logon
Success logins | Total number of successfull logon attempts by the principal
Failed logins | Total number of failed logon attempts by the principal
Log Records Since | Value in this column defines the earliest logon date found on the server. Value will be the same for all records for the same server
