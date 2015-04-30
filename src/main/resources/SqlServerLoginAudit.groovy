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
import io.dbmaster.tools.ldap.LdapUserCache

public class SqlServerLoginAudit { 
    
    static MESSAGE_TO_TYPES = [ "Windows authentication"   : PrincipalType.WINDOWS_LOGIN,
                                "Connection: trusted"       : PrincipalType.WINDOWS_LOGIN,
                                "Connection: non-trusted"   : PrincipalType.SQL_LOGIN,
                                "SQL Server authentication" : PrincipalType.SQL_LOGIN
                              ]
                              
    private static class MsgPattern {
        Pattern pattern
        boolean success
        
        public MsgPattern(String pattern, boolean success) {
            this.pattern = Pattern.compile(pattern)
            this.success = success
        }
    }
    
    def PATTERNS = [
        new MsgPattern("Login succeeded for user '([^']+)'[^\\[]+\\[CLIENT: ([^\\]]*)\\]\\s*", true),
        new MsgPattern("Login failed for user '([^']*)'[^\\[]+\\[CLIENT: ([^\\]]*)\\]\\s*", false),
        new MsgPattern("(user)?The login packet used to open the connection is structurally invalid; the connection has been closed\\. Please contact the vendor of the client library\\. \\[CLIENT: ([^\\]]*)\\]\\s*",false),
        new MsgPattern("Login failed for user '([^']*)'\\. The user is not associated with a trusted SQL Server connection\\. \\[CLIENT: ([^\\]]*)\\]\\s*",false)
    ]
      
    private DbMaster dbm
    private Logger logger
    public  Date since
    java.sql.Timestamp processTime = new java.sql.Timestamp(new Date().getTime())
    
    
    public LdapUserCache ldap
    
    public SqlServerLoginAudit(DbMaster dbm, Logger logger) {
        this.dbm = dbm
        this.logger = logger
        this.ldap = new LdapUserCache(dbm, logger)
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
    
    public List<PrincipalInfo> getLoginAuditList(String[] servers, 
                                                   boolean resolveHosts, 
                                                   String ldapConnection,
                                                   String ldapContext) {
                                                   
        def principalStorageType = "sql account";
        def statisticsStorageType = "sql account statistics";
        
        CustomObjectService customService = dbm.getService(CustomObjectService.class)
        ICustomFieldService cfService = dbm.getService(ICustomFieldService.class)
        List<CustomObjectTypeEntity> types = customService.getCustomObjectTypeList()
        CustomObjectTypeEntity principalType = types.find { it.getObjectName().equals(principalStorageType)}
        CustomObjectTypeEntity principalAuditType = types.find { it.getObjectName().equals(statisticsStorageType)}

        def createField  = { service, metaType, fieldName, fieldType, required, readonly, key = false ->
            CustomFieldConfig field = new CustomFieldConfig()
            field.setName(fieldName)
            field.setType(fieldType)
            field.setRequired(required)
            field.setReadonly(readonly)
            field.setKey(key)
            service.createCustomFieldConfig(metaType, field, false)
        }
        
        if (principalType == null) {
            logger.info("Adding ${principalStorageType} type as it does not exist")

            principalType = new CustomObjectTypeEntity();
            principalType.setObjectName(principalStorageType)
            principalType.setCreate(false)
            principalType.setUpdate(true)
            principalType.setDelete(true)
            
            principalType = customService.createCustomObjectType(principalType)

            createField(cfService, principalType, "Server",Type.STRING,true,true,true)
            createField(cfService, principalType, "Account name",Type.STRING,true,true,true)
            createField(cfService, principalType, "Disabled",Type.BOOLEAN,false,true)
            createField(cfService, principalType, "Account type",Type.STRING,false,true)
            createField(cfService, principalType, "Account owner",Type.STRING,false,false)
            createField(cfService, principalType, "Application",Type.STRING,false,false)
            createField(cfService, principalType, "Review status",Type.STRING,false,false)
            createField(cfService, principalType, "Review date",Type.DATE,false,false)
            createField(cfService, principalType, "Review notes",Type.TEXT,false,false)
        }

        if (principalAuditType == null) {
            logger.info("Adding ${statisticsStorageType} type as it does not exist")
            
            principalAuditType = new CustomObjectTypeEntity();
            principalAuditType.setObjectName(statisticsStorageType);
            principalAuditType.setCreate(false)
            principalAuditType.setUpdate(true)
            principalAuditType.setDelete(true)
            
            principalAuditType = customService.createCustomObjectType(principalAuditType);

            createField(cfService, principalAuditType,"Server",Type.STRING,true,true,true)
            createField(cfService, principalAuditType,"Account name",Type.STRING,true,true,true)
            createField(cfService, principalAuditType,"Source ip",Type.STRING,true,true,true)
            createField(cfService, principalAuditType,"Source host",Type.STRING,false,true)
            createField(cfService, principalAuditType,"Success logons",Type.INTEGER,false,true)
            createField(cfService, principalAuditType,"Last success logon",Type.DATE,false,true)
            createField(cfService, principalAuditType,"Failed logons",Type.INTEGER,false,true)
            createField(cfService, principalAuditType,"Last failed logon",Type.DATE,false,true)
            createField(cfService, principalAuditType,"Review status",Type.STRING,false,false)
            createField(cfService, principalAuditType,"Review date",Type.DATE,false,false)
            createField(cfService, principalAuditType,"Review notes",Type.TEXT,false,false)
        }
                
        List<PrincipalInfo> result = []

        def connectionSrv = dbm.getService(ConnectionService.class)
        
        ldap.loadLdapAccounts(connectionSrv)
        
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
                    new QueryRequest("Server=\"${serverName}\"")).each { row -> 

                    PrincipalInfo principal = new PrincipalInfo()
                    principal.statistics         = new NameMap<LogRecord>();
                    principal.record_id          = row.getId()
                    principal.connection_name    = serverName
                    principal.principal_name     = row.getCustomData("Account name")
                    principal.disabled           = row.getCustomData("Disabled")  // TODO: override
                    principal.principal_type     = row.getCustomData("Account type")      // TODO: override
                    principal.principal_owner    = row.getCustomData("Account owner")
                    principal.principal_app      = row.getCustomData("Application")
                    principal.review_status      = row.getCustomData("Review status")
                    principal.review_date        = row.getCustomData("Review date")
                    principal.review_notes       = row.getCustomData("Review notes")
                    principal.updated_at         = row.getUpdated()
                    principal.updated_by         = row.getUpdateAuthor()
                    
                    userMap[principal.principal_name] = principal
                }
                
                logger.debug("Total principals found ${userMap.size()}")
                
                def query = new QueryRequest("Server=\"${serverName}\"")
                customService.getCustomObjectSlice(principalAuditType.getObjectName(), query)
                .each { row ->
                   
                    def principal = userMap[row.getCustomData("Account name")]
                    // TODO IF PRINCIPAL IS NULL
                    LogRecord log_item = new LogRecord()
                    log_item.record_id          = row.getId()
                    log_item.source_ip          = row.getCustomData("Source ip")
                    log_item.success_logons     = 0 // row.success_logons
                    log_item.last_success_logon = null // row.last_success_logon
                    log_item.failed_logons      = 0 // row.failed_logons
                    log_item.last_failed_logon  = null // row.last_failed_logon
                    log_item.review_status      = row.getCustomData("Review status")
                    log_item.review_notes       = row.getCustomData("Review notes")
                    log_item.review_date        = row.getCustomData("Review date")
                    log_item.updated_at         = row.getUpdated()
                    log_item.updated_by         = row.getUpdateAuthor()
                    
                    principal.statistics[row.getCustomData("Source ip")] = log_item
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

                Statement statement = connection.createStatement()
                
                // log number of log files
                logger.info("Getting number of server log files")
                int count = getLogFileCount(connection)
                
                // load all logs
                logger.info("Parsing files")
                for (int i=0; i<=count; ++i) {
                    if (Thread.interrupted()) {
                        throw new CancellationException();
                    }
                    
                    logger.debug("Parsing file ${i+1} of ${count+1}")
                    statement = connection.createStatement()
                    if (!statement.execute("{call sp_readerrorlog ${i},1,'login'}")) {
                        logger.debug("Stored procedure did not return a result set for file ${i+1}")
                        statement.close();
                        continue;
                    }
                    def rs = statement.getResultSet()
                    while (rs.next()) {
                        if ("Logon".equals(rs.getString(2))) {
                            String msg = rs.getString(3)
                            
                            boolean patternFound = false
                            boolean success
                            String user, ip
                            
                            PATTERNS.each { p -> 
                                Matcher matcher = p.pattern.matcher(msg.trim())
                                if (matcher.matches()) {
                                    success =  p.success
                                    user = matcher.group(1)
                                    ip = matcher.group(2)
                                    patternFound = true
                                    return
                                }
                            }
                            
                            if (!patternFound) { 
                                // TODO (vitaly) - code below does not work
                                logger.warn("Unexpected format of login message: '{}'", 
                                            StringEscapeUtils.escapeJavaScript(msg))
                                continue
                            }
                            if (user==null) {
                                 user = "";
                            }

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
                
                    userMap.values().each { principal ->
                        if (!principal.principal_type.equals("WINDOWS_GROUP")) {
                            def parts = principal.principal_name.split("\\\\");
                            if (parts.length==2) {
                                def domain = parts[0]
                                def username = parts[1]
                                logger.debug("Domain=${domain} user=${username}")
                                
                            def ldapAccount = ldap.ldapAccountByName[principal.principal_name]
                                if (ldapAccount!=null) {
                                def groups = ldap.getSubGroups([], ldapAccount);
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
                object.setCustomData("Server",principal.connection_name);                 
                object.setCustomData("Account name",principal.principal_name)
                object.setCustomData("Disabled",principal.disabled)
                object.setCustomData("Account type",principal.principal_type)
                object.setCustomData("Review status",principal.review_status)
                object.setCustomData("Review notes",principal.review_notes)
                object.setCustomData("Review date",principal.review_date)
                object.setCustomData("Account owner",principal.principal_owner)
                object.setCustomData("Application",principal.principal_app)
                customService.createCustomObject(object)
            } else {
                CustomObjectEntity object = customService.findObjectById(principal.record_id)
                object.setCustomData("Server",principal.connection_name)
                object.setCustomData("Account name",principal.principal_name)
                object.setCustomData("Disabled",principal.disabled)
                object.setCustomData("Account type",principal.principal_type)
                object.setCustomData("Review status",principal.review_status)                
                object.setCustomData("Review notes",principal.review_notes)
                object.setCustomData("Review date",principal.review_date)
                object.setCustomData("Account owner",principal.principal_owner)
                object.setCustomData("Application",principal.principal_app)                
                customService.updateCustomObject(object)
            }
        }
        
        logger.info("Saving statistics")
        result.each { principal ->
            principal.statistics.values().each { log_item ->
                if (log_item.record_id == 0) {
                    CustomObjectEntity object = new CustomObjectEntity()
                    object.setDiscriminator(principalAuditType.getObjectName())
                    object.setCustomData("Server",principal.connection_name)
                    object.setCustomData("Account name",principal.principal_name)
                    object.setCustomData("Source ip",log_item.source_ip)
                    object.setCustomData("Source host",log_item.source_host)
                    object.setCustomData("Success logons",log_item.success_logons)
                    object.setCustomData("Last success logon",log_item.last_success_logon)
                    object.setCustomData("Failed logons",log_item.failed_logons)
                    object.setCustomData("Last failed logon",log_item.last_failed_logon)
                    object.setCustomData("Review status",log_item.review_status)
                    object.setCustomData("Review notes",log_item.review_notes)
                    object.setCustomData("Review date",log_item.review_date)
                    customService.createCustomObject(object)
                } else {
                    CustomObjectEntity object = customService.findObjectById(log_item.record_id)
                    object.setCustomData("Server",principal.connection_name)
                    object.setCustomData("Account name",principal.principal_name)
                    object.setCustomData("Source ip",log_item.source_ip)
                    object.setCustomData("Source host",log_item.source_host)
                    object.setCustomData("Success logons",log_item.success_logons)
                    object.setCustomData("Last success logon",log_item.last_success_logon)
                    object.setCustomData("Failed logons",log_item.failed_logons)
                    object.setCustomData("Last failed logon",log_item.last_failed_logon)
                    object.setCustomData("Review status",log_item.review_status)
                    object.setCustomData("Review notes",log_item.review_notes)
                    object.setCustomData("Review date",log_item.review_date)
                    customService.updateCustomObject(object)
                }
            }
        }
        return result;
    }
}