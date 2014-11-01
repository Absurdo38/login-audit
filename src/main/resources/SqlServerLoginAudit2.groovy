import groovy.json.StringEscapeUtils
import groovy.sql.Sql
import io.dbmaster.tools.login.audit.*

import java.sql.Connection
import java.sql.ResultSet
import java.sql.Statement
import java.util.concurrent.CancellationException
import java.util.regex.Matcher
import java.util.regex.Pattern

import io.dbmaster.tools.ldap.LdapSearch

import javax.naming.*
import javax.naming.directory.*
import javax.naming.ldap.*

import org.slf4j.Logger

import com.branegy.dbmaster.connection.ConnectionProvider
import com.branegy.dbmaster.connection.JdbcConnector
import com.branegy.dbmaster.custom.CustomFieldConfig
import com.branegy.dbmaster.custom.CustomObjectEntity
import com.branegy.dbmaster.custom.CustomObjectService
import com.branegy.dbmaster.custom.CustomObjectTypeEntity
import com.branegy.dbmaster.custom.CustomFieldConfig.Type
import com.branegy.dbmaster.custom.field.server.api.ICustomFieldService
import com.branegy.dbmaster.model.*
import com.branegy.dbmaster.util.NameMap
import com.branegy.scripting.DbMaster
import com.branegy.service.connection.api.ConnectionService
import com.branegy.service.core.QueryRequest

public class SqlServerLoginAudit2 { 
    
    static MESSAGE_TO_TYPES = [ "Windows authentication"   : PrincipalType.WINDOWS_LOGIN,
                                "Connection: trusted"       : PrincipalType.WINDOWS_LOGIN,
                                "Connection: non-trusted"   : PrincipalType.SQL_LOGIN,
                                "SQL Server authentication" : PrincipalType.SQL_LOGIN
                              ]
    private DbMaster dbm
    private Logger logger
    public  Date since
    java.sql.Timestamp processTime = new java.sql.Timestamp(new Date().getTime())
    
    
    public def ldapAccountByDN   = new NameMap()
    public def ldapAccountByName = new NameMap()

    
    public SqlServerLoginAudit2(DbMaster dbm, Logger logger) {
        this.dbm = dbm
        this.logger = logger
    }
     
    private static getMaxDate(Date src,Date newDate) {
       if (src == null) {
           return newDate;
       } else if (newDate.after(src)){
           return newDate;
       } else {
           return src;
       }
    }
    
    private static getMinDate(Date src,Date newDate) {
        if (src == null) {
            return newDate;
        } else if (newDate.before(src)) {
            return newDate;
        } else {
            return src;
        }
    }
    
    private static getLogFileCount(Connection connection) {
        Statement statement = connection.createStatement()
        ResultSet rs = statement.executeQuery("exec master.dbo.xp_enumerrorlogs")
        int count = 0
        while (rs.next()) {
            count = Math.max(count,rs.getInt(1))
        }
        rs.close()
        statement.close()
        return count
    }
    
    public void setupLdapAccounts(String ldapConnection, String ldapContext) {
        if (ldapConnection!=null) {        
            def ldapSearch = new LdapSearch(dbm,logger)    
            def ldap_query  = "(|(objectClass=user)(objectClass=group))"
            // def ldap_attributes = "member;objectClass;sAMAccountName;distinguishedName;description;memberOf;name"
            def ldap_attributes = "member;memberOf;sAMAccountName;distinguishedName;name"
            logger.info("Retrieving ldap accounts and groups")
            def search_results = ldapSearch.search(ldapConnection, ldapContext, ldap_query, ldap_attributes)
            
            def getAll = { ldapAttribute ->
                def result = null
                if (ldapAttribute!=null) {
                    result = []
                    def values = ldapAttribute.getAll()
                    while (values.hasMore()) {
                        result.add(values.next().toString())
                    }
                }
                return result
            }
            
        
            search_results.each { result_item ->  
                Attributes attributes = result_item.getAttributes()
                def name = attributes.get("sAMAccountName")?.get();
                def dn = attributes.get("distinguishedName")?.get();
                def members = getAll(attributes.get("member"))
                def member_of = getAll(attributes.get("memberOf"))
                def title = attributes.get("name")?.get();
                
                // def object_class = getAll(attributes.get("objectClass"))
                
                def account = [ "name" : name, "dn" : dn, "members" : members, "member_of" : member_of, "title": title]
                ldapAccountByDN[dn] = account
                ldapAccountByName[name] = account
            }
        }
    }
    
    private static String getSid() {
        return UUID.randomUUID().toString()
    }
    
    public List<String> getSubGroups (List<String> list, account) {
        account.member_of.each { member_of_dn ->
            def group = ldapAccountByDN[member_of_dn]
            if (group == null) {
                logger.debug("Account for ${member_of_dn} does not exist")
            } else {
                def groupName = group.name
                if (!list.contains(groupName)) {
                    list.add(groupName)
                    getSubGroups(list,group)
                }
            }
        }
        return list
    }
    
    private CustomFieldConfig newField(String name,Type type, boolean required){
        CustomFieldConfig config = new CustomFieldConfig();
        config.setName(name);
        config.setType(type);
        config.setRequired(required);
        return config;
    }

    public List<PrincipalInfo> getLoginAuditList(String[] servers, 
                                                   boolean resolveHosts, 
                                                   String ldapConnection,
                                                   String ldapContext) {
        CustomObjectService customService = dbm.getService(CustomObjectService.class);
        ICustomFieldService customFieldService = dbm.getService(ICustomFieldService.class);
        List<CustomObjectTypeEntity> types = customService.getCustomObjectTypeList();
        CustomObjectTypeEntity principalType = types.find { it.getObjectName().equals("db_principal")};
        CustomObjectTypeEntity principalAuditType = types.find { it.getObjectName().equals("db_principal_audit")};
        if (principalType == null){
            principalType = new CustomObjectTypeEntity();
            principalType.setObjectName("db_principal");
            principalType.setCreate(true);
            principalType.setUpdate(true);
            principalType.setDelete(true);
            
            principalType = customService.createCustomObjectType(principalType);
            
            customFieldService.createCustomFieldConfig(principalType,newField("connection_name",Type.STRING,true),false);
            customFieldService.createCustomFieldConfig(principalType,newField("principal_name",Type.STRING,true),false);
            customFieldService.createCustomFieldConfig(principalType,newField("principal_disabled",Type.BOOLEAN,false),false);
            customFieldService.createCustomFieldConfig(principalType,newField("principal_type",Type.STRING,false),false);
            customFieldService.createCustomFieldConfig(principalType,newField("review_status",Type.STRING,false),false);
            customFieldService.createCustomFieldConfig(principalType,newField("review_notes",Type.TEXT,false),false);
            customFieldService.createCustomFieldConfig(principalType,newField("review_date",Type.DATE,false),false);
            customFieldService.createCustomFieldConfig(principalType,newField("principal_owner",Type.STRING,false),false);
            customFieldService.createCustomFieldConfig(principalType,newField("principal_app",Type.STRING,false),false);
            def key = newField("record_key",Type.STRING,true)
            key.setKey(true);
            customFieldService.createCustomFieldConfig(principalType,key,false);
        }
        if (principalAuditType == null) {
            principalAuditType = new CustomObjectTypeEntity();
            principalAuditType.setObjectName("db_principal_audit");
            principalAuditType.setCreate(true);
            principalAuditType.setUpdate(true);
            principalAuditType.setDelete(true);
            
            principalAuditType = customService.createCustomObjectType(principalAuditType);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("connection_name",Type.STRING,true),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("principal_name",Type.STRING,true),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("source_ip",Type.STRING,true),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("source_host",Type.STRING,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("success_logons",Type.INTEGER,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("last_success_logon",Type.DATE,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("failed_logons",Type.INTEGER,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("last_failed_logon",Type.DATE,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("review_status",Type.STRING,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("review_notes",Type.TEXT,false),false);
            customFieldService.createCustomFieldConfig(principalAuditType,newField("review_date",Type.DATE,false),false);
            def key = newField("record_key",Type.STRING,true)
            key.setKey(true);
            customFieldService.createCustomFieldConfig(principalAuditType,key,false);
        }
                
        List<PrincipalInfo> result = []

        Pattern PATTERN = Pattern.compile("Login (succeeded|failed) for user '([^']+)'[^\\[]+\\[CLIENT: ([^\\]]*)\\]\\s*")
        def connectionSrv = dbm.getService(ConnectionService.class)
        
        setupLdapAccounts(ldapConnection,ldapContext)
        
        def dbConnections
        if (servers!=null && servers.size()>0) {
            dbConnections = servers.collect { serverName -> connectionSrv.findByName(serverName) }
        } else {
            dbConnections = connectionSrv.getConnectionList()
        }
        
        dbConnections.each{ connectionInfo ->
            try {
                def userMap = new NameMap()
                def serverName = connectionInfo.getName()
                                
                def connector = ConnectionProvider.getConnector(connectionInfo)
                if (!(connector instanceof JdbcConnector)) {
                    logger.info("Skipping checks for connection ${serverName} as it is not a database one")
                    return
                } else {
                    logger.info("Connecting to ${serverName}")
                }

                // Load stored principals and logon statistics for the connection
                customService.getCustomObjectSlice(principalType.getObjectName(), 
                    new QueryRequest("connection_name=\"${serverName}\"")).each { row -> 
                    
                    PrincipalInfo principal = new PrincipalInfo()
                    principal.statistics         = new NameMap<LogRecord>();
                    principal.record_id          = row.getId()
                    principal.connection_name    = serverName
                    principal.principal_name     = row.getCustomData("principal_name")
                    principal.disabled           = row.getCustomData("principal_disabled")  // TODO: override
                    principal.principal_type     = row.getCustomData("principal_type")      // TODO: override
                    principal.review_status      = row.getCustomData("review_status")
                    principal.review_notes       = row.getCustomData("review_notes")
                    principal.review_date        = row.getCustomData("review_date")
                    principal.principal_owner    = row.getCustomData("principal_owner")
                    principal.principal_app      = row.getCustomData("principal_app")
                    principal.updated_at         = row.getUpdated()
                    principal.updated_by         = row.getUpdateAuthor()
                    
                    userMap[principal.principal_name] = principal
                }
                
                logger.debug("Total principals found ${userMap.size()}")
                logger.debug("Review date ${userMap["MOVADOGROUP\\bidservice"]?.review_date}")
                logger.debug("Review notes ${userMap["MOVADOGROUP\\bidservice"]?.review_notes}")
                
                def query = new QueryRequest("connection_name=\"${serverName}\"")
                customService.getCustomObjectSlice(principalAuditType.getObjectName(), query)
                .each { row ->
                   
                    def principal = userMap[row.getCustomData("principal_name")]
                    // TODO IF PRINCIPAL IS NULL
                    LogRecord log_item = new LogRecord()
                    log_item.record_id          = row.getId()
                    log_item.source_ip          = row.getCustomData("source_ip")
                    log_item.success_logons     = 0 // row.success_logons
                    log_item.last_success_logon = null // row.last_success_logon
                    log_item.failed_logons      = 0 // row.failed_logons
                    log_item.last_failed_logon  = null // row.last_failed_logon
                    log_item.review_status      = row.getCustomData("review_status")
                    log_item.review_notes       = row.getCustomData("review_notes")
                    log_item.review_date        = row.getCustomData("review_date")
                    log_item.updated_at         = row.getUpdated()
                    log_item.updated_by         = row.getUpdateAuthor()
                    
                    principal.statistics[row.getCustomData("source_ip")] = log_item
                    
                }
                
                Connection connection = connector.getJdbcConnection(null)
                dbm.closeResourceOnExit(connection)
            
                // login list
                logger.info("Getting server principal list")
                
                new Sql(connection).eachRow("""SELECT name, type_desc, is_disabled
                                               FROM sys.server_principals 
                                               WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP') 
                                               ORDER BY name""")
                    { row ->
                        def principal = userMap[row.name]

                        if (principal == null) {
                            principal = new PrincipalInfo()
                            principal.statistics = new NameMap<LogRecord>()
                            userMap[row.name] = principal
                        }

                        principal.connection_name    = serverName
                        principal.principal_name     = row.name
                        principal.disabled           = new Boolean(1 == row.is_disabled)
                        principal.principal_type     = row.type_desc
                        principal.updated_at         = processTime
                        principal.review_status      = "New"
                        // TODO principal.updated_by        = current_user
                    }

                logger.debug("Review 2 date ${userMap["MOVADOGROUP\\bidservice"]?.review_date}")
                logger.debug("Review 2 notes ${userMap["MOVADOGROUP\\bidservice"]?.review_notes}")
   

                Statement statement = connection.createStatement()
                
                // log number of log files
                logger.info("Getting number of server log files")
                int count = getLogFileCount(connection)
                // if (count > 5) count = 5;
                
                // load all logs
                logger.info("Parsing files")
                for (int i=0; i<=count; ++i) {
                    if (Thread.interrupted()) {
                        throw new CancellationException();
                    }
                    
                    logger.debug("Parsing file ${i+1} of ${count+1}")
                    statement = connection.createStatement()
                    if (!statement.execute("{call sp_readerrorlog ${i},1,'login'}")) {
                        logger.warn("Stored procedure did not return a result set for file ${i+1}")
                        statement.close();
                        continue;
                    }
                    def rs = statement.getResultSet()
                    while (rs.next()) {
                        if ("Logon".equals(rs.getString(2))) {
                            String msg = rs.getString(3)
                            Matcher matcher = PATTERN.matcher(msg.trim())
                            if (!matcher.matches()) {
                                // TODO (vitaly) - code below does not work
                                // logger.warn("Unexpected format of login message: '{}'", StringEscapeUtils.escapeHtml(msg))
                                continue
                            }
                            boolean success = "succeeded".equals(matcher.group(1))
                            String user = matcher.group(2)
                            String ip = matcher.group(3)
                            Date logRecordTime = rs.getTimestamp(1)
                            
                            PrincipalInfo principal = userMap[user]

                            if (principal == null) {
                                principal = new PrincipalInfo()
                                principal.statistics         = new NameMap<LogRecord>();

                                userMap[user] = principal

                                principal.connection_name    = serverName
                                principal.principal_name     = user
                                principal.updated_at         = processTime
                                principal.review_status      = "New"
                                principal.principal_type     = PrincipalLogStatus.NOT_ON_SERVER
                                
                                // TODO TODO Get groups                                
                            }
                            
                            LogRecord log_item = principal.statistics[ip]
                            if (log_item == null) {
                                log_item = new LogRecord()
                                log_item.source_ip      = ip
                                log_item.success_logons = 0
                                log_item.updated_at     = processTime
                                log_item.failed_logons  = 0
                                log_item.review_status  = "New"
                                principal.statistics[ip] = log_item
                            }
                            
                            if (success) {
                                log_item.last_success_logon = getMaxDate(log_item.last_success_logon,logRecordTime)
                                log_item.success_logons++
                            } else {
                                log_item.last_failed_logon = getMaxDate(log_item.last_failed_logon, logRecordTime)
                                log_item.failed_logons++
                            }
                            since = getMinDate(since, logRecordTime)
                        }
                    }
                    rs.close()
                    statement.close()
                }
            
                connection.close()               
                result.addAll(userMap.values())
                                
                if (resolveHosts) {
                    logger.info("Resolving hosts")
                    userMap.values().each { principal ->
                        principal.statistics.values().each { log_item ->
                            if (log_item.source_ip != null) {
                                try {
                                    logger.debug("Resolving ${log_item.source_ip}")                                    
                                    log_item.source_host = InetAddress.getByName(log_item.source_ip).getCanonicalHostName()
                                } catch (UnknownHostException uhe) {
                                    log_item.source_host = log_item.source_ip
                                }
                            }
                        }
                    }
                }
                
                // calculate groups
                if (ldapConnection!=null) {
                    userMap.values().each { principal ->
                        if (!principal.principal_type.equals("WINDOWS_GROUP")) {
                            def parts = principal.principal_name.split("\\\\");
                            if (parts.length==2) {
                                def domain = parts[0]
                                def username = parts[1]
                                logger.debug("Domain=${domain} user=${username}")
                                
                                def ldapAccount = ldapAccountByName[username]
                                if (ldapAccount!=null) {
                                    def groups = getSubGroups([], ldapAccount);
                                    groups.each { group ->
                                        def fullName = domain + "\\" + group;
                                        if (userMap[fullName]!=null) {
                                            principal.linkAccount(fullName);
                                            userMap[fullName].linkAccount(principal.principal_name);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } catch (CancellationException e) {
                throw e;
            } catch (Exception e) {
                def msg = "Error occurred "+e.getMessage()
                org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e)
                logger.error(msg, e)
            }
        }
        result.sort { a, b -> a.connection_name.compareToIgnoreCase(b.connection_name)*10000+
                              a.principal_name.compareToIgnoreCase(b.principal_name) }
        
        // Saving principals
        logger.info("Saving principals")
        

        result.each { principal ->
            if (principal.record_id == 0) {
                CustomObjectEntity object = new CustomObjectEntity()
                object.setDiscriminator(principalType.getObjectName())
                object.setCustomData("connection_name",principal.connection_name);                 
                object.setCustomData("principal_name",principal.principal_name)
                object.setCustomData("disabled",principal.disabled)
                object.setCustomData("principal_type",principal.principal_type)
                object.setCustomData("review_status",principal.review_status)
                object.setCustomData("review_notes",principal.review_notes)
                object.setCustomData("review_date",principal.review_date)
                object.setCustomData("principal_owner",principal.principal_owner)
                object.setCustomData("principal_app",principal.principal_app)
                object.setCustomData("record_key",getSid())
                customService.createCustomObject(object)
            } else {
                CustomObjectEntity object = customService.findObjectById(principal.record_id)
                object.setCustomData("connection_name",principal.connection_name)
                object.setCustomData("principal_name",principal.principal_name)
                object.setCustomData("disabled",principal.disabled)
                object.setCustomData("principal_type",principal.principal_type)
                object.setCustomData("review_status",principal.review_status)                
                object.setCustomData("review_notes",principal.review_notes)
                object.setCustomData("review_date",principal.review_date)
                object.setCustomData("principal_owner",principal.principal_owner)
                object.setCustomData("principal_app",principal.principal_app)
                
                if (principal.principal_name.equals("MOVADOGROUP\\bidservice")) {
                    logger.debug("Review 3 date ${principal.review_date}")
                    logger.debug("Review 3 notes ${principal.review_notes}")                    
                }

                customService.updateCustomObject(object)
            }
        }
        
        logger.info("Saving statistics")
        result.each { principal ->
            principal.statistics.values().each { log_item ->
                if (log_item.record_id == 0) {
                    CustomObjectEntity object = new CustomObjectEntity()
                    object.setDiscriminator(principalAuditType.getObjectName())
                    object.setCustomData("connection_name",principal.connection_name)
                    object.setCustomData("principal_name",principal.principal_name)
                    object.setCustomData("source_ip",log_item.source_ip)
                    object.setCustomData("source_host",log_item.source_host)
                    object.setCustomData("success_logons",log_item.success_logons)
                    object.setCustomData("last_success_logon",log_item.last_success_logon)
                    object.setCustomData("failed_logons",log_item.failed_logons)
                    object.setCustomData("last_failed_logon",log_item.last_failed_logon)
                    object.setCustomData("review_status",log_item.review_status)
                    object.setCustomData("review_notes",log_item.review_notes)
                    object.setCustomData("review_date",log_item.review_date)
                    object.setCustomData("record_key",getSid())
                    customService.createCustomObject(object)
                } else {
                    CustomObjectEntity object = customService.findObjectById(log_item.record_id)
                    object.setCustomData("connection_name",principal.connection_name)
                    object.setCustomData("principal_name",principal.principal_name)
                    object.setCustomData("source_ip",log_item.source_ip)
                    object.setCustomData("source_host",log_item.source_host)
                    object.setCustomData("success_logons",log_item.success_logons)
                    object.setCustomData("last_success_logon",log_item.last_success_logon)
                    object.setCustomData("failed_logons",log_item.failed_logons)
                    object.setCustomData("last_failed_logon",log_item.last_failed_logon)
                    object.setCustomData("review_status",log_item.review_status)
                    object.setCustomData("review_notes",log_item.review_notes)
                    object.setCustomData("review_date",log_item.review_date)
                    customService.updateCustomObject(object)
                }
            }
        }
        return result;
    }

}