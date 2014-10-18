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


// import com.branegy.dbmaster.util.NameMap



connectionSrv = dbm.getService(ConnectionService.class)
connectionInfo = connectionSrv.findByName(p_ldap_connection)
connector = ConnectionProvider.getConnector(connectionInfo)

// TODO Check if connector is ldap
def context = connector.connect().getContext()
dbm.closeResourceOnExit(context)

def String escapeDN(String name) {
    /*StringBuilder sb = new StringBuilder();
    if ((name.length() > 0) && ((name.charAt(0) == ' ') || (name.charAt(0) == '#'))) {
        sb.append('\\'); // add the leading backslash if needed
    }
    for (int i = 0; i < name.length(); i++) {
        char curChar = name.charAt(i);
        switch (curChar) {
            case '\\':
                sb.append("\\\\");
                break;
            case ',':
                sb.append("\\,");
                break;
            case '+':
                sb.append("\\+");
                break;
            case '"':
                sb.append("\\\"");
                break;
            case '<':
                sb.append("\\<");
                break;
            case '>':
                sb.append("\\>");
                break;
            case ';':
                sb.append("\\;");
                break;
            default:
                sb.append(curChar);
        }
    }
    if ((name.length() > 1) && (name.charAt(name.length() - 1) == ' ')) {
        sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
        }
    return sb.toString();*/
    return name.replace("\\", "\\\\");
}

def getDistinguishedName(Attributes attrs){
    return attrs.get("distinguishedName").getAll().next().toString();
}

def getValue(Attributes attrs,String name){
    return "<span style=\"color:#d3d3d3;\">"+name+":</span> "+attrs.get(name).getAll().next().toString();
}

def search(Deque<Attributes> stack, String groupName, DirContext context, 
           SearchControls ctrl, Logger logger, int level) {

    if (contains(stack, groupName)) {
        return;
    }
    
    NamingEnumeration enumeration = context.
        search(p_ldap_context, String.format("(distinguishedName=%s)",escapeDN(groupName)), ctrl);

    if (!enumeration.hasMore()) {
        return; 
    }
    
    Attributes attribs = ((SearchResult) enumeration.next()).getAttributes();
    Attribute attr = attribs.get("objectClass")
    if (!attr.contains("group")){
        return;
    }
    
    logger.info(escapeDN(groupName));
    println  StringUtils.repeat("&nbsp;&nbsp;", level*2)+getValue(attribs,"name")
            +" " + getValue(attribs,"sAMAccountName")+"<br/>";
    
    attr = attribs.get("member")
    NamingEnumeration<Attribute> e = attr.getAll();
    if (e.hasMore()){
        while (e.hasMore()){
            groupName = e.next();
            stack.addLast(attribs);
            search(stack, groupName, context, ctrl, logger, level+1);
            stack.removeLast();
        };
    //} else {
    //    println stack.toString()+"<br/>";
    }
}

def contains(Collection<Attributes> collection, String name) {
    for (Attributes a:collection) {
        if (getDistinguishedName(a).equals(name)) {
            return true;
        }
    }
    return false;
}


SearchControls ctrl = new SearchControls();
// a candidate for script parameter
ctrl.setSearchScope(SearchControls.SUBTREE_SCOPE);
// a candidate for script parameter
ctrl.setCountLimit(100000);
// a candidate for script parameter
ctrl.setTimeLimit(10000); // 10 second == 10000 ms

/*if (p_attributes!=null && p_attributes.length()>0) {
    def attrIDs = p_attributes.split(";")
    ctrl.setReturningAttributes(attrIDs);
}*/
//println "<table border=\"1\">"


def connectionSrv = dbm.getService(ConnectionService.class)
Sql sql = null       
logger.info("Connecting to ${p_server}")
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


    def row = sql.firstRow(query, [ p_principal ])
    if (row == null) {
            println "Principal ${p_principal} not found at server ${p_server}";
    } else { 
        println """ <h1>Principal ${p_principal} info at server ${p_server}</h1>
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
    


Deque<Attributes> stack = new ArrayDeque<Attributes>();

def idx = p_principal.indexOf('\\');
def ldap_query = "(sAMAccountName=${idx>0 ? p_principal.substring(idx+1) : p_principal})"

logger.debug("Query = ${ldap_query}")

NamingEnumeration enumeration = context.search(p_ldap_context, ldap_query, ctrl)
int index = 0
try {
    while (enumeration.hasMore()) {
        SearchResult result = (SearchResult) enumeration.next();
        Attributes attribs = result.getAttributes();
        Attribute attr =  attribs.get("objectClass")
        if (attr.contains("user")) {
           attr = attribs.get("memberOf");
           if (attr != null){
               NamingEnumeration<Attribute> e = attr.getAll(); // group name
               while (e.hasMore()){
                  String groupName = e.next();
                  search(stack, groupName, context, ctrl, logger,0);
               }
           }
        }
    }
}  catch (SizeLimitExceededException e) {
    // for paging see
    // http://www.forumeasy.com/forums/thread.jsp?tid=115756126876&fid=ldapprof2&highlight=LDAP+Search+Paged+Results+Control
}

/*

WITH role_members AS (

SELECT rp.name root_role, rm.role_principal_id, rp.name, rm.member_principal_id,mp.name as member_name, mp.sid, 1 as depth  
FROM sys.server_role_members rm
 inner join sys.server_principals rp on rp.principal_id = rm.role_principal_id
 inner join sys.server_principals mp on mp.principal_id = rm.member_principal_id

UNION ALL

SELECT cte.root_role, cte.member_principal_id, cte.member_name, rm.member_principal_id,mp.name as member_name, mp.sid, cte.depth +1
FROM sys.server_role_members rm
 inner join sys.server_principals mp on mp.principal_id = rm.member_principal_id
 inner join role_members cte on cte.member_principal_id = rm.role_principal_id
)
SELECT distinct root_role from role_members where member_name='WRR\dipesh'



---------------------------------

create table #tempschema (database_name sysname,role_name sysname,principal_name sysname)
 
INSERT INTO #tempschema
EXEC sp_MSForEachDB '
USE [?];
WITH role_members AS (

SELECT rp.name root_role, rm.role_principal_id, rp.name, rm.member_principal_id,mp.name as member_name, mp.sid, 1 as depth  
FROM sys.database_role_members rm
 inner join sys.database_principals rp on rp.principal_id = rm.role_principal_id
 inner join sys.database_principals mp on mp.principal_id = rm.member_principal_id

UNION ALL

SELECT cte.root_role, cte.member_principal_id, cte.member_name, rm.member_principal_id,mp.name as member_name, mp.sid, cte.depth +1
FROM sys.database_role_members rm
 inner join sys.database_principals mp on mp.principal_id = rm.member_principal_id
 inner join role_members cte on cte.member_principal_id = rm.role_principal_id
)
SELECT distinct ''?'',root_role, sp.name from role_members rm
inner join sys.server_principals sp on rm.sid= sp.sid 
where sp.name = ''WRR\crystal''
'

select distinct * from #tempschema
drop table #tempschema

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




SELECT
log.name,
log.type,
log.type_desc,
ISNULL(log.default_language_name,N'') AS [Language],
l.alias AS [LanguageAlias],
ISNULL(log.default_database_name, N'') AS [DefaultDatabase],
CAST(CASE sp.state WHEN N'D' THEN 1 ELSE 0 END AS bit) AS [DenyWindowsLogin],
CASE WHEN N'U' = log.type THEN 0 WHEN N'G' = log.type THEN 1 WHEN N'S' = log.type THEN 2 WHEN N'C' = log.type THEN 3 WHEN N'K' = log.type THEN 4 END AS [LoginType],
CASE WHEN (N'U' != log.type AND N'G' != log.type) THEN 99 WHEN (sp.state is null) THEN 0 WHEN (N'G'=sp.state) THEN 1 ELSE 2 END AS [WindowsLoginAccessType],
CAST(CASE WHEN (sp.state is null) THEN 0 ELSE 1 END AS bit) AS [HasAccess],
log.sid AS [Sid],
log.create_date AS [CreateDate],
log.modify_date AS [DateLastModified],
CAST(LOGINPROPERTY(log.name, N'IsLocked') AS bit) AS [IsLocked],
CAST(LOGINPROPERTY(log.name, N'IsExpired') AS bit) AS [IsPasswordExpired],
CAST(LOGINPROPERTY(log.name, N'IsMustChange') AS bit) AS [MustChangePassword],
log.principal_id AS [ID],
ISNULL(c.name,N'') AS [Credential],
ISNULL(cert.name,N'') AS [Certificate],
ISNULL(ak.name,N'') AS [AsymmetricKey],
log.is_disabled AS [IsDisabled],
CAST(CASE WHEN log.principal_id < 256 THEN 1 ELSE 0 END AS bit) AS [IsSystemObject],
CAST(sqllog.is_expiration_checked AS bit) AS [PasswordExpirationEnabled],
CAST(sqllog.is_policy_checked AS bit) AS [PasswordPolicyEnforced]
FROM
sys.server_principals AS log
LEFT OUTER JOIN sys.syslanguages AS l ON l.name = log.default_language_name
LEFT OUTER JOIN sys.server_permissions AS sp ON sp.grantee_principal_id = log.principal_id and sp.type = N'COSQ'
LEFT OUTER JOIN sys.credentials AS c ON c.credential_id = log.credential_id
LEFT OUTER JOIN master.sys.certificates AS cert ON cert.sid = log.sid
LEFT OUTER JOIN master.sys.asymmetric_keys AS ak ON ak.sid = log.sid
LEFT OUTER JOIN sys.sql_logins AS sqllog ON sqllog.principal_id = log.principal_id
WHERE
(log.type in ('U', 'G', 'S', 'C', 'K') AND log.principal_id not between 101 and 255 AND log.name <> N'##MS_AgentSigningCertificate##')and(log.name='Movadogroup\svdavichen')



*/