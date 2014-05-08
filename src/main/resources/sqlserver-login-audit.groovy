import java.text.SimpleDateFormat;
import java.text.DateFormat;
import java.util.regex.Matcher;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.ResultSetMetaData;
import java.util.*
import java.util.regex.Pattern;

import com.branegy.dbmaster.database.api.ModelService
import com.branegy.dbmaster.model.*
import com.branegy.service.connection.api.ConnectionService
import com.branegy.dbmaster.connection.ConnectionProvider

import org.apache.commons.io.IOUtils

import java.sql.Connection

import com.branegy.dbmaster.connection.JdbcConnector

import org.apache.commons.lang.StringEscapeUtils;

enum PrincipalLogStatus { NOT_ON_SERVER, NOT_IN_LOG, ACTIVE }

enum PrincipalType { SQL_LOGIN, WINDOWS_LOGIN, UNKNOWN }

def MESSAGE_TO_TYPES = [ "Windows authentication"   : PrincipalType.WINDOWS_LOGIN,
                        "Connection: trusted"       : PrincipalType.WINDOWS_LOGIN,
                        "Connection: non-trusted"   : PrincipalType.SQL_LOGIN,
                        "SQL Server authentication" : PrincipalType.SQL_LOGIN
                       ]


class LogRecord {
    String sourceIP
    PrincipalType principalType
    Date lastSuccessDate
    Date lastFailedDate
    int successCount
    int failedCount
}

class UserInfo {
    String server
    // NULL means we don't know
    Boolean principalDisabled
    PrincipalLogStatus logStatus = PrincipalLogStatus.ACTIVE
    // map of ip_address+principalType (we can find logins of different type at sql server and in log)
    Map<String, LogRecord> ipMap = [:]
}

def getMaxDate(Date src,Date newDate) {
   if (src == null) {
       return newDate;
   } else if (newDate.after(src)){
       return newDate;
   } else {
       return src;
   }
}

def getMinDate(Date src,Date newDate) {
    if (src == null) {
        return newDate;
    } else if (newDate.before(src)) {
        return newDate;
    } else {
        return src;
    }
 }

def getLogCount(Connection connection) {
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

def getNotNull(Object o) {
    if (o instanceof Date) {
        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).format(o)
    }
    return o == null? "" : o.toString()
}


println """<table cellspacing='0' class='simple-table' border='1'>"""
println """<tr style="background-color:#EEE">"""
println "<td>Server</td>"
println "<td>Principal</td>"
println "<td>Principal Status</td>"
println "<td>Type</td>"
println "<td>Source</td>"
if (p_resolve_hosts) {
    println "<td>Host</td>"
}
println "<td>Successful Logins</td>"
println "<td>Last Success Time</td>"
println "<td>Failed Logins</td>"
println "<td>Last Failed Time</td>"
println "<td>Principal Log Status</td>"
println "<td>Log Records Since</td>"
println "</tr>"

Pattern PATTERN = Pattern.compile("Login (succeeded|failed) for user '([^']+)'[^\\[]+\\[CLIENT: ([^\\]]*)\\]\\s*");

connectionSrv = dbm.getService(ConnectionService.class)

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
        connector = ConnectionProvider.getConnector(connectionInfo)
        if (!(connector instanceof JdbcConnector)) {
            logger.info("Skipping checks for connection ${serverName} as it is not a database one")
            return
        } else {
            logger.info("Connecting to ${serverName}")
        }
        
        connection = connector.getJdbcConnection(null)
        dbm.closeResourceOnExit(connection)
    
        // login list
        logger.info("Getting server principal list")

        def sqlServerPrincipals = [:]
        statement = connection.createStatement()
        def sqlQuery  = """SELECT name, 
                                  CASE WHEN type_desc = 'SQL_LOGIN' THEN 0 ELSE 1 END,
                                  is_disabled
                           FROM sys.server_principals 
                           WHERE type_desc IN ('SQL_LOGIN','WINDOWS_LOGIN') 
                           ORDER BY name"""
        
        rs = statement.executeQuery(sqlQuery)
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
        Statement statement = null
        ResultSet rs = null
        Date since = null
        for (int i=0; i<=count; ++i){
            statement = connection.createStatement()
            logger.debug("Parsing file ${i} of ${count+1}")
            rs = statement.executeQuery("exec sp_readerrorlog ${i},1,'login'")
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
                
                println """<tr>
                             <td>${userInfo.server}</td>
                             <td>${principalName}</td>
                             <td>${userInfo.principalDisabled ==null ? "Unknown" : (userInfo.principalDisabled ? "Disabled" : "Enabled")}</td>
                             <td>${getNotNull(logRecord.principalType)}</td>
                             <td>${StringEscapeUtils.escapeHtml(getNotNull(logRecord.sourceIP))}</td>"""

                if (p_resolve_hosts) {
                    String ip = logRecord.sourceIP
                    println "<td>"
                    if (ip != null) {
                        try {
                            print InetAddress.getByName(ip).getCanonicalHostName()
                        } catch (UnknownHostException uhe) {
                            print StringEscapeUtils.escapeHtml(ip)
                        }
                    }
                    println "</td>"
                }
                println "<td style='text-align:right'>${logRecord.successCount}</td>"
                println "<td>${getNotNull(logRecord.lastSuccessDate)}</td>"
                println "<td style='text-align:right'>${logRecord.failedCount}</td>"
                println "<td>${getNotNull(logRecord.lastFailedDate)}</td>"
                println "<td>${getNotNull(userInfo.logStatus)}</td>"
                println "<td>${getNotNull(since)}</td>"
                println "</tr>"
            }
        }
    } catch (Exception e) {
        def msg = "Error occurred "+e.getMessage()
        org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e)
        logger.error(msg, e)
    }
}
println "</table>"