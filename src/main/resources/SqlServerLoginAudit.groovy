import java.text.SimpleDateFormat;
import java.text.DateFormat;
import java.util.regex.Matcher;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.ResultSetMetaData;
import java.util.*
import java.util.regex.Pattern;
import com.branegy.scripting.DbMaster
import org.slf4j.Logger;

import com.branegy.dbmaster.database.api.ModelService
import com.branegy.dbmaster.model.*
import com.branegy.service.connection.api.ConnectionService
import com.branegy.dbmaster.connection.ConnectionProvider

import org.apache.commons.io.IOUtils

import java.sql.Connection

import com.branegy.dbmaster.connection.JdbcConnector

import org.apache.commons.lang.StringEscapeUtils;


public abstract class SqlServerLoginAudit{ 
    enum PrincipalLogStatus { NOT_ON_SERVER, NOT_IN_LOG, ACTIVE }
    
    enum PrincipalType { SQL_LOGIN, WINDOWS_LOGIN, WINDOWS_GROUP, UNKNOWN }
    
    static MESSAGE_TO_TYPES = [ "Windows authentication"   : PrincipalType.WINDOWS_LOGIN,
                               "Connection: trusted"       : PrincipalType.WINDOWS_LOGIN,
                               "Connection: non-trusted"   : PrincipalType.SQL_LOGIN,
                               "SQL Server authentication" : PrincipalType.SQL_LOGIN
                              ]
    
    static class LogRecord {
        String sourceIP
        PrincipalType principalType
        Date lastSuccessDate
        Date lastFailedDate
        int successCount
        int failedCount
    }
    
    static class UserInfo {
        String server
        // NULL means we don't know
        Boolean principalDisabled
        PrincipalLogStatus logStatus = PrincipalLogStatus.ACTIVE
        // map of ip_address+principalType (we can find logins of different type at sql server and in log)
        Map<String, LogRecord> ipMap = [:]
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
    
    private static getLogCount(Connection connection) {
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
    
    public static List<Object[]> getLoginAuditList(DbMaster dbm, Logger logger, String[] p_servers, boolean p_resolve_hosts){
        List<Object[]> result = [];
        
        
        Pattern PATTERN = Pattern.compile("Login (succeeded|failed) for user '([^']+)'[^\\[]+\\[CLIENT: ([^\\]]*)\\]\\s*");
        def connectionSrv = dbm.getService(ConnectionService.class)
        
        def dbConnections
        if (p_servers!=null && p_servers.size()>0) {
            dbConnections = p_servers.collect { serverName -> connectionSrv.findByName(serverName) }
        } else {
            dbConnections  = connectionSrv.getConnectionList()
        }
        
        dbConnections.each{ connectionInfo ->
            try {
                def userMap = [:]
                def serverName = connectionInfo.getName()
                def connector = ConnectionProvider.getConnector(connectionInfo)
                if (!(connector instanceof JdbcConnector)) {
                    logger.info("Skipping checks for connection ${serverName} as it is not a database one")
                    return
                } else {
                    logger.info("Connecting to ${serverName}")
                }
                
                Connection connection = connector.getJdbcConnection(null)
                dbm.closeResourceOnExit(connection)
            
                // login list
                logger.info("Getting server principal list")
        
                def sqlServerPrincipals = [:]
                Statement statement = connection.createStatement()
                def sqlQuery  = """SELECT name, 
                                          CASE WHEN type_desc = 'SQL_LOGIN' THEN 0 ELSE 1 END,
                                          is_disabled
                                   FROM sys.server_principals 
                                   WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN','WINDOWS_GROUP') 
                                   ORDER BY name"""
                
                ResultSet rs = statement.executeQuery(sqlQuery)
                while (rs.next()) {
                   String userName = rs.getString(1)
                   PrincipalType principalType = PrincipalType.values()[rs.getInt(2)]
                   Boolean disabled = new Boolean(1 == rs.getInt(3))
                   sqlServerPrincipals.put(userName, ["principalType":principalType, "disabled":disabled])
                }
                rs.close()
                statement.close()
            
                // log record count
                int count = getLogCount(connection)
                // load all logs
                Date since = null
                for (int i=0; i<=count; ++i){
                    logger.debug("Parsing file ${i+1} of ${count+1}")
                    statement = connection.createStatement()
                    if (!statement.execute("{call sp_readerrorlog ${i},1,'login'}")){
                        logger.warn("Stored procedure did not return a result set for file ${i+1}");
                        statement.close();
                        continue;
                    }
                    rs = statement.getResultSet();
                    while (rs.next()){
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
                            
                            def principalTypeFromLog = PrincipalType.UNKNOWN
                            MESSAGE_TO_TYPES.each { pattern, type ->
                                if (msg.contains(pattern)) {
                                    principalTypeFromLog = type
                                    return
                                }
                            }
                            UserInfo userInfo = userMap.get(user)
                            if (userInfo == null) {
                                userInfo = new UserInfo()
                                userInfo.server = serverName
                                if (!sqlServerPrincipals.containsKey(user)) {
                                    userInfo.logStatus = PrincipalLogStatus.NOT_ON_SERVER
                                } else {
                                    userInfo.principalDisabled = sqlServerPrincipals.get(user)["disabled"]
                                }
                                userMap.put(user, userInfo)
                            }
                            
                            if (principalTypeFromLog==PrincipalType.UNKNOWN && sqlServerPrincipals.containsKey(user)) {
                                principalTypeFromLog = sqlServerPrincipals.get(user)["principalType"]
                            }
                            
                            LogRecord rec = userInfo.ipMap.get(ip+principalTypeFromLog)
                            if (rec == null) {
                                rec = new LogRecord()
                                rec.sourceIP = ip
                                rec.principalType = principalTypeFromLog
                                userInfo.ipMap.put(ip+principalTypeFromLog, rec)
                            }
                            
                            if (success) {
                                rec.lastSuccessDate = getMaxDate(rec.lastSuccessDate,logRecordTime)
                                rec.successCount++
                            } else {
                                rec.lastFailedDate = getMaxDate(rec.lastFailedDate, logRecordTime)
                                rec.failedCount++
                            }
                            since = getMinDate(since, logRecordTime)
                        }
                    }
                    rs.close()
                    statement.close()
                }
            
                // Add principals that were not found at sql server
                sqlServerPrincipals.keySet().removeAll(userMap.keySet())
                for (Map.Entry<String,PrincipalType> e: sqlServerPrincipals.entrySet()) {
                   UserInfo userInfo = new UserInfo()
                   userInfo.server = serverName
                   userInfo.logStatus = PrincipalLogStatus.NOT_IN_LOG
                   userInfo.principalDisabled = e.getValue()["disabled"]
                   LogRecord rec = new LogRecord()
                   rec.principalType = e.getValue()["principalType"]
                   userInfo.ipMap.put(null, rec)
                   userMap.put(e.getKey(), userInfo)
                }
            
                connection.close()
                
                List<Map.Entry<String,UserInfo>> elist = new ArrayList<Map.Entry<String,UserInfo>>(userMap.entrySet())
                elist.sort { a, b -> a.key.compareToIgnoreCase(b.key) }
                
                elist.each { entry ->
                    def principalName = entry.getKey()
                    def userInfo = entry.getValue()
                    userInfo.ipMap.values().each { logRecord ->
                        Object[] row = new Object[12];
                        int index = 0;
                        row[index++] = userInfo.server;
                        row[index++] = principalName;
                        row[index++] = userInfo.principalDisabled;
                        row[index++] = logRecord.principalType;
                        row[index++] = logRecord.sourceIP;
                        
                        if (p_resolve_hosts) {
                            String ip = logRecord.sourceIP
                            if (ip != null) {
                                try {
                                    row[index] = InetAddress.getByName(ip).getCanonicalHostName()
                                } catch (UnknownHostException uhe) {
                                    row[index] = ip;
                                }
                            }
                            index++;
                        }
                        
                        row[index++] = logRecord.successCount;
                        row[index++] = logRecord.lastSuccessDate;
                        row[index++] = logRecord.failedCount;
                        row[index++] = logRecord.lastFailedDate;
                        row[index++] = userInfo.logStatus;
                        row[index++] = since;
                        
                        result.add(row);
                    }
                }
            } catch (Exception e) {
                def msg = "Error occurred "+e.getMessage()
                org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e)
                logger.error(msg, e)
            }
        }
        return result;
    }

}