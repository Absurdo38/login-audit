import java.text.SimpleDateFormat
import java.text.DateFormat
import java.util.regex.Matcher
import java.sql.ResultSet
import java.sql.Statement
import java.sql.Connection
import java.sql.ResultSetMetaData
import java.util.*
import java.util.regex.Pattern
import java.util.concurrent.CancellationException

import groovy.sql.Sql

import org.slf4j.Logger
import org.apache.commons.io.IOUtils
import org.apache.commons.lang.StringEscapeUtils

import com.branegy.scripting.DbMaster
import com.branegy.dbmaster.database.api.ModelService
import com.branegy.dbmaster.model.*
import com.branegy.service.connection.api.ConnectionService
import com.branegy.dbmaster.connection.ConnectionProvider
import com.branegy.dbmaster.connection.JdbcConnector
import io.dbmaster.tools.login.audit.*
import com.branegy.dbmaster.util.NameMap

public class SqlServerLoginAudit { 
    
    static MESSAGE_TO_TYPES = [ "Windows authentication"   : PrincipalType.WINDOWS_LOGIN,
                                "Connection: trusted"       : PrincipalType.WINDOWS_LOGIN,
                                "Connection: non-trusted"   : PrincipalType.SQL_LOGIN,
                                "SQL Server authentication" : PrincipalType.SQL_LOGIN
                              ]
    private DbMaster dbm
    private Logger logger
    public  Date since
    java.sql.Timestamp processTime = new java.sql.Timestamp(new Date().getTime())
    
    public SqlServerLoginAudit(DbMaster dbm, Logger logger) {
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
    
    public List<PrincipalInfo> getLoginAuditList(String[] servers, 
                                                   boolean resolveHosts, 
                                                   String ldapConnection,
                                                   String ldapContext,
                                                   String storageDB) {
        List<PrincipalInfo> result = []

        Pattern PATTERN = Pattern.compile("Login (succeeded|failed) for user '([^']+)'[^\\[]+\\[CLIENT: ([^\\]]*)\\]\\s*")
        def connectionSrv = dbm.getService(ConnectionService.class)
        
        Sql storageSql = null
        
        if (storageDB!=null) {
            def server_name    = storageDB.split("\\.")[0]
            def database_name  = storageDB.split("\\.")[1]

            def connector = ConnectionProvider.getConnector(connectionSrv.findByName(server_name))
            if (!(connector instanceof JdbcConnector)) {
                // TODO: have to be an error
                logger.info("Storage is not a database. Skipping storage option")
            } else {
                logger.info("Connecting to storage at ${server_name} database ${database_name}")
                def storageConnection = connector.getJdbcConnection(database_name)
                dbm.closeResourceOnExit(storageConnection)
                storageSql = Sql.newInstance(storageConnection)
            }
        }
        
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
                if (storageSql!=null) {
                    storageSql.eachRow("""select record_id,principal_name,principal_disabled,
                                                 principal_type,review_status,review_notes,review_date,
                                                 principal_owner,principal_app,updated_at,updated_by
                                            from dbm_db_principal
                                           where connection_name = $serverName""") 
                    { row ->
                        PrincipalInfo principal = new PrincipalInfo()
                        principal.statistics         = new NameMap<LogRecord>();
                        principal.record_id          = row.record_id
                        principal.connection_name    = serverName
                        principal.principal_name     = row.principal_name
                        principal.disabled           = row.principal_disabled   // TODO: override
                        principal.principal_type     = row.principal_type       // TODO: override
                        principal.review_status      = row.review_status
                        principal.review_notes       = row.review_notes
                        
                        if (principal.review_notes instanceof java.sql.Clob) {
                            principal.review_notes = IOUtils.toString(principal.review_notes.getCharacterStream())
                        }
                        
                        principal.review_date        = row.review_date 
                        principal.principal_owner    = row.principal_owner
                        principal.principal_app      = row.principal_app
                        principal.updated_at         = row.updated_at
                        principal.updated_by         = row.updated_by
                        
                        userMap[row.principal_name] = principal
                    }
                    
                    storageSql.eachRow("""select record_id, principal_name, source_ip,
                                                 source_host,success_logons,last_success_logon,failed_logons,
                                                 last_failed_logon,review_status,review_notes,review_date,
                                                 updated_at,updated_by
                                            from dbm_db_principal_audit
                                           where connection_name = $serverName""") 
                    { row ->
                        def principal = userMap[row.principal_name]
                        // TODO IF PRINCIPAL IS NULL
                        LogRecord log_item = new LogRecord()
                        log_item.record_id          = row.record_id
                        log_item.source_ip          = row.source_ip
                        // logRecord.source_host        = row.source_host
                        log_item.success_logons     = 0 // row.success_logons
                        log_item.last_success_logon = null // row.last_success_logon
                        log_item.failed_logons      = 0 // row.failed_logons
                        log_item.last_failed_logon  = null // row.last_failed_logon
                        log_item.review_status      = row.review_status
                        log_item.review_notes       = row.review_notes
                        log_item.review_date        = row.review_date
                        log_item.updated_at         = row.updated_at
                        log_item.updated_by         = row.updated_by
                        
                        principal.statistics[row.source_ip] = log_item
                    }
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
                // if (count > 5) count = 5;
                
                // load all logs
                logger.info("Parsing files")
                // Date since = null
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
                                logger.warn("Unexpected format of login message: '{}'", StringEscapeUtils.escapeHtml(msg))
                                continue
                            }
                            boolean success = "succeeded".equals(matcher.group(1))
                            String user = matcher.group(2)
                            String ip = matcher.group(3)
                            Date logRecordTime = rs.getTimestamp(1)
                            
                            // def principalTypeFromLog = PrincipalType.UNKNOWN
                            // MESSAGE_TO_TYPES.each { pattern, type ->
                            //    if (msg.contains(pattern)) {
                            //        principalTypeFromLog = type
                            //        return
                            //    }
                            //}
                            
                            
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
        if (storageSql!=null) {
            try { 
                logger.info("Saving principals")
                result.each { principal ->
                    String query;
                    def queryParameters;
                    if (principal.record_id == 0) {
                        query = """insert into dbo.dbm_db_principal (
                                      connection_name,principal_name,principal_disabled,
                                      principal_type,review_status,review_notes,review_date,
                                      principal_owner,principal_app,updated_at,updated_by )
                                   values (?,?,?,?,?,?,?,?,?,?,?)"""
                                      
                        queryParameters =  [
                                principal.connection_name,
                                principal.principal_name,
                                principal.disabled == null ? null : principal.disabled ? 1 : 0,
                                principal.principal_type,
                                principal.review_status,
                                principal.review_notes,
                                principal.review_date,
                                principal.principal_owner,
                                principal.principal_app,
                                principal.updated_at,
                                principal.updated_by ]
                        
                    } else {
                        query = """update dbo.dbm_db_principal set
                                      connection_name=?,principal_name=?,principal_disabled=?,
                                      principal_type=?,review_status=?,review_notes=?,review_date=?,
                                      principal_owner=?,principal_app=?,updated_at=?,updated_by=? where record_id=?"""
                                      
                        queryParameters =  [
                                principal.connection_name,
                                principal.principal_name,
                                principal.disabled == null ? null : principal.disabled ? 1 : 0,
                                principal.principal_type,
                                principal.review_status,
                                principal.review_notes,
                                principal.review_date,
                                principal.principal_owner,
                                principal.principal_app,
                                principal.updated_at,
                                principal.updated_by,
                                principal.record_id ]
                    }
                    storageSql.executeUpdate(query, queryParameters)
                }
                logger.info("Saving statistics")

                result.each { principal ->
                    principal.statistics.values().each { log_item ->
                        String query
                        def queryParameters
                        if (log_item.record_id == 0) {
                            query = """insert into dbo.dbm_db_principal_audit (
                                          connection_name,principal_name,source_ip,source_host,
                                          success_logons,last_success_logon,failed_logons,last_failed_logon,
                                          review_status,review_notes,review_date,updated_at,updated_by
                                        )
                                       values (?,?,?,?,?,?,?,?,?,?,?,?,?)"""

                            queryParameters =  [
                                    principal.connection_name,
                                    principal.principal_name,
                                    log_item.source_ip,
                                    log_item.source_host,
                                    log_item.success_logons,
                                    log_item.last_success_logon,
                                    log_item.failed_logons,
                                    log_item.last_failed_logon,
                                    log_item.review_status,
                                    log_item.review_notes,
                                    log_item.review_date,
                                    log_item.updated_at,
                                    log_item.updated_by ]
                            
                        } else {
                            query = """update dbo.dbm_db_principal_audit set
                                          connection_name=?,principal_name=?,source_ip=?,source_host=?,
                                          success_logons=?,last_success_logon=?,failed_logons=?,last_failed_logon=?,
                                          review_status=?,review_notes=?,review_date=?,updated_at=?,updated_by=?
                                       where record_id=?"""
                                          
                            queryParameters =  [
                                    principal.connection_name,
                                    principal.principal_name,
                                    log_item.source_ip,
                                    log_item.source_host,
                                    log_item.success_logons,
                                    log_item.last_success_logon,
                                    log_item.failed_logons,
                                    log_item.last_failed_logon,
                                    log_item.review_status,
                                    log_item.review_notes,
                                    log_item.review_date,
                                    log_item.updated_at,
                                    log_item.updated_by,
                                    log_item.record_id ]
                        }
                        storageSql.executeUpdate(query, queryParameters)
                    }
                }
                storageSql.commit()
            } catch (Exception e) {
                logger.error("Cannot save data ${e.message()}")
                e.printStackTrace()
                storageSql.rollback()
            } finally {
                storageSql.close()
            }
        }
        return result;
    }

}