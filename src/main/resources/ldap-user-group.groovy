import javax.naming.*;
import javax.naming.directory.*;

import com.branegy.service.connection.api.ConnectionService;
import com.branegy.dbmaster.connection.ConnectionProvider;

import java.util.ArrayDeque;
import java.util.logging.Level;

import org.slf4j.Logger;
import org.apache.commons.lang.StringUtils;

connectionSrv = dbm.getService(ConnectionService.class);
connectionInfo = connectionSrv.findByName(p_connection)
connector = ConnectionProvider.getConnector(connectionInfo)

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

def search(Deque<Attributes> stack, String groupName, DirContext context, SearchControls ctrl, Logger logger, int level){
    if (contains(stack, groupName)){
        return;
    }
    
    NamingEnumeration enumeration = context.search(p_base_context, String.format("(distinguishedName=%s)",escapeDN(groupName)), ctrl);
    if (!enumeration.hasMore()){
        return; 
    }
    Attributes attribs = ((SearchResult) enumeration.next()).getAttributes();
    Attribute attr = attribs.get("objectClass")
    if (!attr.contains("group")){
        return;
    }
    
    logger.info(escapeDN(groupName));
    println  StringUtils.repeat("&nbsp;&nbsp;", level*2)+getValue(attribs,"name")+" " + getValue(attribs,"sAMAccountName")+"<br/>";
    
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

def contains(Collection<Attributes> collection, String name){
    for (Attributes a:collection){
        if (getDistinguishedName(a).equals(name)){
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

Deque<Attributes> stack = new ArrayDeque<Attributes>();
NamingEnumeration enumeration = context.search(p_base_context, p_query, ctrl);
int index = 0
try {
    while (enumeration.hasMore()) {
        SearchResult result = (SearchResult) enumeration.next();
        Attributes attribs = result.getAttributes();
        Attribute attr =  attribs.get("objectClass")
        if (attr.contains("user")){
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
