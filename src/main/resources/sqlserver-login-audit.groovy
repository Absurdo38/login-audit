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

enum Principal{
    NOT_IN_LIST,
    NOT_IN_LOG,
    ACTIVE;
}

enum LoginType{
    SQL_LOGIN, WINDOWS_LOGIN;
}

class LogRecord{
    LoginType loginType;
    Date lastSuccessDate;
    Date lastFailedDate;
    int successCount;
    int failedCount;
}

class UserInfo{
    String server;
    Principal principal = Principal.ACTIVE;
    Map<String,LogRecord> ipMap = [:]; 
}

def getLastDate(Date src,Date newDate){
   if (src == null){
       return newDate;
   } else if (newDate.after(src)){
       return newDate;
   } else {
       return src;
   }
}

def getFirstDate(Date src,Date newDate){
    if (src == null){
        return newDate;
    } else if (newDate.before(src)){
        return newDate;
    } else {
        return src;
    }
 }

def getLogCount(Connection connection){
    Statement statement = connection.createStatement();
    ResultSet rs = statement.executeQuery("exec master.dbo.xp_enumerrorlogs");
    int count = 0;
    while (rs.next()){
        count = Math.max(count,rs.getInt(1));
    }
    rs.close();
    statement.close();
    return count;
}

def getNotNull(Object o){
    if (o instanceof Date){
        return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT, Locale.US).format(o);
    }
    return o == null? "" : o.toString();
}


println """<table cellspacing='0' class='simple-table' border='1'>"""
println """<tr style="background-color:#EEE">"""
println "<td>Server</td>"
println "<td>Principal</td>"
println "<td>Type</td>"
println "<td>Status</td>"
println "<td>Source</td>"
println "<td>Last Success Time</td>"
println "<td>Last Failed Time</td>"
println "<td>Successed Logins</td>"
println "<td>Failed Logins</td>"
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
        def userMap = [:];
        def serverName = connectionInfo.getName()
        connector = ConnectionProvider.getConnector(connectionInfo)
        if (!(connector instanceof JdbcConnector)) {
            logger.info("Skipping checks for connection ${serverName} as it is not a database one")
            return
        } else {
            logger.info("Connecting to ${serverName}")
        }
        
        connection = connector.getJdbcConnection(null);
        dbm.closeResourceOnExit(connection);
    
        // login list
        def loginMap = [:]
        statement = connection.createStatement();
        rs = statement.executeQuery("select name, CASE WHEN type_desc = 'SQL_LOGIN' THEN 0 ELSE 1 END from sys.server_principals where type_desc in ('SQL_LOGIN','WINDOWS_LOGIN') order by name");
        while (rs.next()){
           String userName = rs.getString(1);
           LoginType loginType = LoginType.values()[rs.getInt(2)];
           loginMap.put(userName, loginType); 
        }
        statement.close();
        rs.close();
    
        // log record count
        int count = getLogCount(connection);
        // load all logs
        Statement statement = null;
        ResultSet rs = null;
        Date since = null;
        for (int i=0; i<=count; ++i){
            statement = connection.createStatement();
            rs = statement.executeQuery("exec sp_readerrorlog ${i},1,'login'");
            while (rs.next()){
                if ("Logon".equals(rs.getString(2))){
                    String msg = rs.getString(3);
                    Matcher matcher = PATTERN.matcher(msg.trim());
                    if (!matcher.matches()){
                        logger.warn("Unparsed data: '{}'", StringEscapeUtils.escapeHtml(msg));
                        continue;
                    }
                    boolean success = "succeeded".equals(matcher.group(1));
                    String user = matcher.group(2);
                    String ip = matcher.group(3);
                    Date date = rs.getTimestamp(1);
                    
                    UserInfo info = userMap.get(user);
                    if (info == null){
                        info = new UserInfo();
                        info.server = serverName;
                        if (!loginMap.containsKey(user)){
                            info.principal = Principal.NOT_IN_LIST;
                        }
                        userMap.put(user,info);
                    }
                    
                    LogRecord rec = info.ipMap.get(ip);
                    if (rec == null){
                        rec = new LogRecord();
                        if (info.principal == Principal.NOT_IN_LIST){
                           rec.loginType = msg.contains("Windows authentication")? LoginType.WINDOWS_LOGIN : LoginType.SQL_LOGIN;
                        } else {
                           rec.loginType = loginMap.get(user);
                        }
                        info.ipMap.put(ip, rec);
                    }
                    
                    if (success){
                        rec.lastSuccessDate = getLastDate(rec.lastSuccessDate,date);
                        rec.successCount++;
                    } else {
                        rec.lastFailedDate = getLastDate(rec.lastFailedDate,date);
                        rec.failedCount++;
                    }
                    since = getFirstDate(since, date);
                }
            }
            statement.close();
            rs.close(); 
        }
        loginMap.keySet().removeAll(userMap.keySet());
    
        for (Map.Entry<String,LoginType> e:loginMap.entrySet()){
           UserInfo info = new UserInfo();
           info.server = serverName;
           info.principal = Principal.NOT_IN_LOG;
           LogRecord rec = new LogRecord();
           rec.loginType = e.getValue();
           info.ipMap.put(null, rec);
           userMap.put(e.getKey(),info);
        }
    
        connection.commit();
        
        List<Map.Entry<String,UserInfo>> elist = new ArrayList<Map.Entry<String,UserInfo>>(userMap.entrySet()).sort{
            a, b -> a.key.compareToIgnoreCase(b.key)
        }
        for (Map.Entry<String,UserInfo> e:elist){
            UserInfo i = e.getValue();
            for (Map.Entry<String,LogRecord> e2:i.ipMap.entrySet()){
                LogRecord r = e2.getValue();
                
                println "<tr>"
                println "<td>${i.server}</td>"
                println "<td>${e.getKey()}</td>"
                println "<td>${getNotNull(r.loginType)}</td>"
                println "<td>${getNotNull(i.principal)}</td>"
                println "<td>${StringEscapeUtils.escapeHtml(getNotNull(e2.getKey()))}</td>"
                println "<td>${getNotNull(r.lastSuccessDate)}</td>"
                println "<td>${getNotNull(r.lastFailedDate)}</td>"
                println "<td style='text-align:right'>${r.successCount}</td>"
                println "<td style='text-align:right'>${r.failedCount}</td>"
                println "<td>${getNotNull(since)}</td>"
                println "</tr>"
            }
        }
    } catch (Exception e) {
        def msg = "Error occurred "+e.getMessage()
        org.slf4j.LoggerFactory.getLogger(this.getClass()).error(msg,e);
        logger.error(msg, e)
    }
}
println "</table>"    