package io.dbmaster.tools.login.audit;

import java.sql.Timestamp;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;

public class PrincipalInfo implements java.io.Serializable {
        int record_id;
        String connection_name;
        String principal_name;
        String principal_type;
        // NULL means we don't know
        Boolean disabled;
        String review_status;
        String review_notes;
        Timestamp review_date;
        String principal_owner;
        String principal_app;
        Timestamp updated_at;
        String updated_by;
        
        // PrincipalLogStatus logStatus = PrincipalLogStatus.ACTIVE
        // map of ip_address+principalType (we can find logins of different type at sql server and in log)        
        Map<String, LogRecord> statistics;
        
        Set<String> linked_accounts;
        
        public synchronized void linkAccount(String account) {
            if (linked_accounts==null) {
                linked_accounts = new HashSet<String>();
            }
            linked_accounts.add(account);
        }
}