import java.text.SimpleDateFormat
import java.text.DateFormat

import org.apache.commons.lang.StringEscapeUtils


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
println "<td>Logon IP / Host</td>"
println "<td>Successful Logins</td>"
println "<td>Last Success Time</td>"
println "<td>Failed Logins</td>"
println "<td>Last Failed Time</td>"
println "<td>Log Records Since</td>"
println "</tr>"

def loginAudit =new SqlServerLoginAudit(dbm, logger)
result = loginAudit.getLoginAuditList(p_servers, p_resolve_hosts, p_ldap_connection, p_ldap_context)
                                  
result.each { principal ->

    println "<tr valign=\"top\">"
    int rows = principal.statistics.size()
    if (rows==0) { rows = 1 }
    
    println "<td rowspan=\"${rows}\">${principal.connection_name}</td>"
    
    print "<td rowspan=\"${rows}\">"
    print tool_linker.set("id","db-principal-info")
                     .set("p_server",principal.connection_name)
                     .set("p_ldap_connection",p_ldap_connection)
                     .set("p_ldap_context",p_ldap_context)
                     .set("p_principal",principal.principal_name)
                     .render(principal.principal_name).toString()
    if (principal.review_status!=null) {
        println ("<br/>Review Status: ${principal.review_status}")
    }       
    if (principal.review_notes!=null) {
        println ("<br/>Review Notes: ${principal.review_notes}")
    }
    if (principal.review_date!=null) {
        println ("<br/>Review Date: ${getNotNull(principal.review_date)}")
    }
    if (principal.principal_owner!=null) {
        println ("<br/>Account Owner: ${principal.principal_owner}")
    }
    if (principal.principal_app!=null) {
        println ("<br/>Application: ${principal.principal_app}")
    }
    if (!getNotNull(principal.principal_type).equals("WINDOWS_GROUP") 
        && principal.linked_accounts!=null && principal.linked_accounts.size()>0) {

        println ("<br/>Groups: "+principal.linked_accounts.join("; "))
    }

    println "</td>"
    println "<td rowspan=\"${rows}\">${principal.disabled == null ? "" : (principal.disabled ? "disabled" : "enabled" )}</td>"
    println "<td rowspan=\"${rows}\">${getNotNull(principal.principal_type)}</td>"
    
    if (principal.statistics.size()==0) {
        def msg = "No logon records"
        
        if (getNotNull(principal.principal_type).equals("WINDOWS_GROUP") && 
            principal.linked_accounts!=null && principal.linked_accounts.size()>0) {
            msg = "Used by accounts: " + principal.linked_accounts.join("; ")
        }

        println "<td colspan=\"5\">${msg}</td>"
        println "<td>${getNotNull(loginAudit.since)}</td>"
    }
    boolean first = true;
    principal.statistics.values().each { stat ->
        if (!first) { println("</tr><tr>"); }
        first = false;
        println "<td>${StringEscapeUtils.escapeHtml(getNotNull(stat.source_ip))}"
        if (p_resolve_hosts) {
            println " <br/>Host: ${StringEscapeUtils.escapeHtml(getNotNull(stat.source_host))}"
        }
        if (stat.review_status!=null) {
            println ("<br/>Review Status: ${stat.review_status}")
        }       
        if (stat.review_date!=null) {
            println ("<br/>Review Date: ${getNotNull(stat.review_date)}")
        }
        if (stat.review_notes!=null) {
            println ("<br/>Notes: ${stat.review_notes}")
        }
        println "</td>"
        println "<td style='text-align:right'>${stat.success_logons}</td>"
        println "<td>${getNotNull(stat.last_success_logon)}</td>"
        println "<td style='text-align:right'>${stat.failed_logons}</td>"
        println "<td>${getNotNull(stat.last_failed_logon)}</td>"
        println "<td>${getNotNull(loginAudit.since)}</td>"
    }
    println "</tr>"
}
println "</table>"