package io.dbmaster.tools.login.audit;

import java.sql.Timestamp;

public class LogRecord implements java.io.Serializable {

    int record_id;
    String source_ip;
        
    String source_host;
    int success_logons;
    Timestamp last_success_logon;
    int failed_logons;
    Timestamp last_failed_logon;
    String review_status;
    String review_notes;
    Timestamp review_date;

    Timestamp updated_at;
    String updated_by;
}