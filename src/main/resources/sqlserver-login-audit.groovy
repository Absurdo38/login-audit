import java.text.SimpleDateFormat;
import java.text.DateFormat;
import org.apache.commons.lang.StringEscapeUtils;

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

result = SqlServerLoginAudit.getLoginAuditList(dbm,logger, p_servers, p_resolve_hosts);
for (Object[] v: result) {
    println "<tr>"
    println "<td>${v[0]}</td>"
    println "<td>${v[1]}</td>"
    println "<td>${v[2]}</td>"
    println "<td>${getNotNull(v[3])}</td>"
    println "<td>${StringEscapeUtils.escapeHtml(getNotNull(v[4]))}</td>"
    int index = 5;
    if (p_resolve_hosts) {
        println " <td>${StringEscapeUtils.escapeHtml(v[index++])}</td>"
    }
    println "<td style='text-align:right'>${v[index++]}</td>"
    println "<td>${getNotNull(v[index++])}</td>"
    println "<td style='text-align:right'>${v[index++]}</td>"
    println "<td>${getNotNull(v[index++])}</td>"
    println "<td>${getNotNull(v[index++])}</td>"
    println "<td>${getNotNull(v[index++])}</td>"
    println "</tr>"
}
println "</table>"