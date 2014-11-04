import javax.naming.*
import javax.naming.directory.*

import com.branegy.service.connection.api.ConnectionService
import com.branegy.dbmaster.connection.ConnectionProvider
import com.branegy.dbmaster.connection.JdbcConnector

import java.util.ArrayDeque
import java.util.logging.Level

import org.slf4j.Logger
import org.apache.commons.lang.StringUtils
import groovy.sql.Sql

connectionSrv = dbm.getService(ConnectionService.class)

def connectionSrv = dbm.getService(ConnectionService.class)
Sql sql = null       
logger.info("Connecting to database server ${p_server}")
def connector = ConnectionProvider.getConnector(connectionSrv.findByName(p_server))

if (!(connector instanceof JdbcConnector)) {
    // TODO: have to be an error
    logger.info("Connection is not a database one")
    return
} else {
    def sqlConnection = connector.getJdbcConnection(null)
    dbm.closeResourceOnExit(sqlConnection)
    sql = Sql.newInstance(sqlConnection)
}

def query = """
    SELECT  log.name,
            log.type,
            log.type_desc,
            ISNULL(log.default_language_name,N'') AS [Language],
            l.alias AS [LanguageAlias],
            ISNULL(log.default_database_name, N'') AS [DefaultDatabase],
            CAST(CASE sp.state WHEN N'D' THEN 1 ELSE 0 END AS bit) AS [DenyWindowsLogin],
            CASE WHEN N'U' = log.type THEN 0 WHEN N'G' = log.type THEN 1 WHEN N'S' = log.type THEN 2 WHEN N'C' = log.type THEN 3 WHEN N'K' = log.type THEN 4 END AS [LoginType],
            CASE WHEN (N'U' != log.type AND N'G' != log.type) THEN 99 WHEN (sp.state is null) THEN 0 WHEN (N'G'=sp.state) THEN 1 ELSE 2 END AS [WindowsLoginAccessType],
            CAST(CASE WHEN (sp.state is null) THEN 0 ELSE 1 END AS bit) AS [HasAccess],
            log.sid AS [sid],
            log.create_date AS [CreateDate],
            log.modify_date AS [DateLastModified],
            CAST(LOGINPROPERTY(log.name, N'IsLocked') AS bit) AS [IsLocked],
            CAST(LOGINPROPERTY(log.name, N'IsExpired') AS bit) AS [IsPasswordExpired],
            CAST(LOGINPROPERTY(log.name, N'IsMustChange') AS bit) AS [MustChangePassword],
            log.principal_id,
            ISNULL(c.name,N'') AS [Credential],
            ISNULL(cert.name,N'') AS [Certificate],
            ISNULL(ak.name,N'') AS [AsymmetricKey],
            log.is_disabled AS [IsDisabled],
            CAST(CASE WHEN log.principal_id < 256 THEN 1 ELSE 0 END AS bit) AS [IsSystemObject],
            CAST(sqllog.is_expiration_checked AS bit) AS [PasswordExpirationEnabled],
            CAST(sqllog.is_policy_checked AS bit) AS [PasswordPolicyEnforced]
    FROM    sys.server_principals AS log
    LEFT OUTER JOIN sys.syslanguages AS l ON l.name = log.default_language_name
    LEFT OUTER JOIN sys.server_permissions AS sp ON sp.grantee_principal_id = log.principal_id and sp.type = N'COSQ'
    LEFT OUTER JOIN sys.credentials AS c ON c.credential_id = log.credential_id
    LEFT OUTER JOIN master.sys.certificates AS cert ON cert.sid = log.sid
    LEFT OUTER JOIN master.sys.asymmetric_keys AS ak ON ak.sid = log.sid
    LEFT OUTER JOIN sys.sql_logins AS sqllog ON sqllog.principal_id = log.principal_id
    WHERE UPPER(log.name)=UPPER(?) """

    def hexadecimal(binvalue) {
        def hexstring = '0123456789ABCDEF'
        def charvalue = '0x'
        binvalue.each {
           def xx = it < 0 ? (256 + it) : it
           charvalue+= hexstring[((int)xx/16)]+hexstring[xx%16]
        }
        return charvalue
    }

    logger.info("Getting principal info")
    def row = sql.firstRow(query, [ p_principal ])
    def principal_id
    
    if (row == null) {
            println "Principal ${p_principal} not found at server ${p_server}";
    } else {
        principal_id = row.principal_id
        println """ <h2>Principal ${p_principal} info at server ${p_server}</h2>
                    <table>
                        <tr><td>Name</td><td>${row.name}</td></tr>
                        <tr><td>Type</td><td>${row.type_desc}</td></tr>
                        <tr><td>Language</td><td>${row.Language} ( ${row.LanguageAlias})</td></tr>
                        <tr><td>Default Database</td><td>${row.DefaultDatabase}</td></tr>
                        <tr><td>DenyWindowsLogin</td><td>${row.DenyWindowsLogin}</td></tr>
                        <tr><td>WindowsLoginAccessType</td><td>${row.WindowsLoginAccessType}</td></tr>
                        <tr><td>HasAccess</td><td>${row.HasAccess}</td></etr>
                        <tr><td>SID</td><td>${hexadecimal(row.sid)}</td></tr>
                        <tr><td>Create date</td><td>${row.CreateDate}</td></tr>
                        <tr><td>Date last modified</td><td>${row.DateLastModified}</td></tr>
                        <tr><td>IsLocked</td><td>${row.IsLocked}</td></tr>
                        <tr><td>IsPasswordExpired</td><td>${row.IsPasswordExpired}</td></tr>
                        <tr><td>MustChangePassword</td><td>${row.MustChangePassword}</td></tr>
                        <tr><td>ID</td><td>${row.principal_id}</td></tr>
                        <tr><td>Disabled</td><td>${row.IsDisabled}</td></tr>
                        <tr><td>IsSystemObject</td><td>${row.IsSystemObject}</td></tr>
                        <tr><td>PasswordExpirationEnabled</td><td>${row.PasswordExpirationEnabled}</td></tr>
                        <tr><td>PasswordPolicyEnforced</td><td>${row.PasswordPolicyEnforced}</td></tr>
                    </table>
                """
    }
    
query = """
            WITH role_members AS (
                SELECT rp.name root_role, rm.role_principal_id, rp.name, rm.member_principal_id,mp.name as member_name, mp.sid, 1 as depth  
                FROM sys.server_role_members rm
                INNER JOIN sys.server_principals rp on rp.principal_id = rm.role_principal_id
                INNER JOIN sys.server_principals mp on mp.principal_id = rm.member_principal_id

                UNION ALL

                SELECT cte.root_role, cte.member_principal_id, cte.member_name, rm.member_principal_id,mp.name as member_name, mp.sid, cte.depth +1
                FROM sys.server_role_members rm
                INNER JOIN sys.server_principals mp on mp.principal_id = rm.member_principal_id
                INNER JOIN role_members cte on cte.member_principal_id = rm.role_principal_id
            )
            SELECT DISTINCT root_role FROM role_members WHERE member_principal_id=?
        """

logger.info("Getting server roles")
        
def rows  = sql.rows(query, [principal_id] )

println "<h2>Server roles</h2>"
if (rows.size()==0) { 
    println "<div>No server roles defined</div>" 
} else {
    println "<div>${rows.collect { it.root_role }.join(",")}</div>" 
}

logger.info("Getting database roles")

sql.execute("create table #tempschema (database_name sysname,role_name sysname,principal_name sysname)")
 
sql.execute("""INSERT INTO #tempschema
EXEC sp_MSForEachDB '
USE [?];
WITH role_members AS (

SELECT rp.name root_role, 
       rm.role_principal_id, 
       rp.name, 
       rm.member_principal_id,
       mp.name as member_name, 
       mp.sid, 
       1 as depth  
FROM sys.database_role_members rm
 inner join sys.database_principals rp on rp.principal_id = rm.role_principal_id
 inner join sys.database_principals mp on mp.principal_id = rm.member_principal_id

UNION ALL

SELECT cte.root_role, cte.member_principal_id, cte.member_name, rm.member_principal_id,mp.name as member_name, mp.sid, cte.depth +1
FROM sys.database_role_members rm
 inner join sys.database_principals mp on mp.principal_id = rm.member_principal_id
 inner join role_members cte on cte.member_principal_id = rm.role_principal_id
)
SELECT distinct ''?'' as database_name,root_role as role_name, sp.name from role_members rm
inner join sys.server_principals sp on rm.sid=sp.sid 
where sp.principal_id = ${principal_id}'""".toString())

rows  = sql.rows("select distinct * from #tempschema")

sql.execute("drop table #tempschema")

println "<h2>Database roles</h2>"
logger.debug(query)
// rows  = sql.rows(query.toString())

if (rows.size()==0) { 
    println "<div>No database roles defined</div>" 
} else {
    println "<table>"
    rows.each { r -> 
        println "<tr><td>${r.database_name}</td><td>${r.role_name}</td></tr>"
    }
    println "</table>"
}

    def printAttr(String attribute, String value) {
        return "<span style=\"color:#d3d3d3;\">"+attribute+":</span> "+value;
    }

    def printSubGroups (loginAudit, account, level) {
        if (account.member_of==null) {
            return
        }
        
        account.member_of.each { member_of_dn ->
            def group = loginAudit.ldapAccountByDN[member_of_dn]
            if (group == null) {
                logger.debug("Account for ${member_of_dn} does not exist")
            } else {
                println  StringUtils.repeat("&nbsp;&nbsp;", level*2) +
                         printAttr("name", group.title)+" " + printAttr("sAMAccountName",group.name)+"<br/>";
                def groupName = group.name
                //if (!list.contains(groupName)) {
                    //list.add(groupName)
                    printSubGroups(loginAudit, group, level+1)
                //}
            }
        }
    }

    def printMembers (loginAudit, account, level ) {
        if (account.members==null) {
            return
        }

        account.members.each { member_dn ->
            def member = loginAudit.ldapAccountByDN[member_dn]
            if (member == null) {
                logger.debug("Account for ${member_of_dn} does not exist")
            } else {
                println  StringUtils.repeat("&nbsp;&nbsp;", level*2) +
                         printAttr("name", member.title)+" " + printAttr("sAMAccountName",member.name)+"<br/>";
                printMembers(loginAudit, member, level+1)
            }
        }
    }

    logger.info("Retrieving active directory information")
    def loginAudit = new SqlServerLoginAudit(dbm,logger)
    loginAudit.setupLdapAccounts(p_ldap_connection, p_ldap_context)
   
    def idx = p_principal.indexOf('\\')
    def accountName = idx>0 ? p_principal.substring(idx+1) : p_principal
    def account = loginAudit.ldapAccountByName[accountName]
    if (account == null) {
        logger.info("Account ${accountName} not found in active directory")
    } else {
        if (account.member_of!=null && account.member_of.size()>0) {
            println "<h2>Active Directory: Group Membership for ${accountName}</h2>"
            printSubGroups(loginAudit, account, 0)
        }
        if (account.members!=null && account.members.size()>0) {
            println "<h2>Active Directory: Members of ${accountName}</h2>"
            printMembers(loginAudit, account, 0)
        }
    }


/*

-------------------------------------------


SELECT CASE WHEN P.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN 'GRANT' ELSE P.state_desc END AS cmd_state,
       P.permission_name,
       'ON '+ CASE P.class_desc
           WHEN 'DATABASE' THEN 'DATABASE::'+QUOTENAME(DB_NAME())
           WHEN 'SCHEMA' THEN 'SCHEMA::'+QUOTENAME(S.name)
           WHEN 'OBJECT_OR_COLUMN' THEN 'OBJECT::'+QUOTENAME(OS.name)+'.'+QUOTENAME(O.name)+
             CASE WHEN P.minor_id <> 0 THEN '('+QUOTENAME(C.name)+')' ELSE '' END
           WHEN 'DATABASE_PRINCIPAL' THEN
             CASE PR.type_desc 
               WHEN 'SQL_USER' THEN 'USER'
               WHEN 'DATABASE_ROLE' THEN 'ROLE'
               WHEN 'APPLICATION_ROLE' THEN 'APPLICATION ROLE'
             END +'::'+QUOTENAME(PR.name)
           WHEN 'ASSEMBLY' THEN 'ASSEMBLY::'+QUOTENAME(A.name)
           WHEN 'TYPE' THEN 'TYPE::'+QUOTENAME(TS.name)+'.'+QUOTENAME(T.name)
           WHEN 'XML_SCHEMA_COLLECTION' THEN 'XML SCHEMA COLLECTION::'+QUOTENAME(XSS.name)+'.'+QUOTENAME(XSC.name)
           WHEN 'SERVICE_CONTRACT' THEN 'CONTRACT::'+QUOTENAME(SC.name)
           WHEN 'MESSAGE_TYPE' THEN 'MESSAGE TYPE::'+QUOTENAME(SMT.name)
           WHEN 'REMOTE_SERVICE_BINDING' THEN 'REMOTE SERVICE BINDING::'+QUOTENAME(RSB.name)
           WHEN 'ROUTE' THEN 'ROUTE::'+QUOTENAME(R.name)
           WHEN 'SERVICE' THEN 'SERVICE::'+QUOTENAME(SBS.name)
           WHEN 'FULLTEXT_CATALOG' THEN 'FULLTEXT CATALOG::'+QUOTENAME(FC.name)
           WHEN 'FULLTEXT_STOPLIST' THEN 'FULLTEXT STOPLIST::'+QUOTENAME(FS.name)
           -- WHEN 'SEARCH_PROPERTY_LIST' THEN 'SEARCH PROPERTY LIST::'+QUOTENAME(RSPL.name)
           WHEN 'SYMMETRIC_KEYS' THEN 'SYMMETRIC KEY::'+QUOTENAME(SK.name)
           WHEN 'CERTIFICATE' THEN 'CERTIFICATE::'+QUOTENAME(CER.name)
           WHEN 'ASYMMETRIC_KEY' THEN 'ASYMMETRIC KEY::'+QUOTENAME(AK.name)
         END COLLATE Latin1_General_100_BIN AS securable,
         'TO '+QUOTENAME(DP.name) AS grantee,
         CASE WHEN P.state_desc = 'GRANT_WITH_GRANT_OPTION' THEN 'WITH GRANT OPTION' ELSE '' END AS grant_option,
         'AS '+QUOTENAME(G.name) AS grantor
  FROM sys.database_permissions AS P
  LEFT JOIN sys.schemas AS S
    ON P.major_id = S.schema_id
  LEFT JOIN sys.all_objects AS O
       JOIN sys.schemas AS OS
         ON O.schema_id = OS.schema_id
    ON P.major_id = O.object_id
  LEFT JOIN sys.types AS T
       JOIN sys.schemas AS TS
         ON T.schema_id = TS.schema_id
    ON P.major_id = T.user_type_id
  LEFT JOIN sys.xml_schema_collections AS XSC
       JOIN sys.schemas AS XSS
         ON XSC.schema_id = XSS.schema_id
    ON P.major_id = XSC.xml_collection_id
  LEFT JOIN sys.columns AS C
    ON O.object_id = C.object_id
   AND P.minor_id = C.column_id
  LEFT JOIN sys.database_principals AS PR
    ON P.major_id = PR.principal_id
  LEFT JOIN sys.assemblies AS A
    ON P.major_id = A.assembly_id
  LEFT JOIN sys.service_contracts AS SC
    ON P.major_id = SC.service_contract_id
  LEFT JOIN sys.service_message_types AS SMT
    ON P.major_id = SMT.message_type_id
  LEFT JOIN sys.remote_service_bindings AS RSB
    ON P.major_id = RSB.remote_service_binding_id
  LEFT JOIN sys.services AS SBS
    ON P.major_id = SBS.service_id
  LEFT JOIN sys.routes AS R
    ON P.major_id = R.route_id
  LEFT JOIN sys.fulltext_catalogs AS FC
    ON P.major_id = FC.fulltext_catalog_id
  LEFT JOIN sys.fulltext_stoplists AS FS
    ON P.major_id = FS.stoplist_id
  -- LEFT JOIN sys.registered_search_property_lists AS RSPL
   --  ON P.major_id = RSPL.property_list_id
  LEFT JOIN sys.asymmetric_keys AS AK
    ON P.major_id = AK.asymmetric_key_id
  LEFT JOIN sys.certificates AS CER
    ON P.major_id = CER.certificate_id
  LEFT JOIN sys.symmetric_keys AS SK
    ON P.major_id = SK.symmetric_key_id
  JOIN sys.database_principals AS DP
    ON P.grantee_principal_id = DP.principal_id
  JOIN sys.database_principals AS G
    ON P.grantor_principal_id = G.principal_id
 --WHERE P.grantee_principal_id IN (USER_ID('TestUser1'), USER_ID('TestUser2'));

where not DP.name like '%public%'


*/  