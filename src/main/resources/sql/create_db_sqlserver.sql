CREATE TABLE [dbo].[dbm_db_principal](
	[record_id] [int] IDENTITY(1,1) NOT NULL,
	[connection_name] [varchar](128) NOT NULL,
	[principal_name] [varchar](128) NOT NULL,
	[principal_disabled] [tinyint] NULL,
	[principal_type] [varchar](32) NULL,
	[review_status] [varchar](32) NULL,
	[review_notes] [varchar](4000) NULL,
	[review_date] [datetime] NULL,
	[principal_owner] [varchar](1024) NULL,
	[principal_app] [varchar](128) NULL,
	[updated_at] [datetime] NOT NULL,
	[updated_by] [varchar](50) NULL,
    CONSTRAINT [PK_dbm_login_info] PRIMARY KEY CLUSTERED ([record_id] ASC)
    WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) 
    ON [PRIMARY]
) ON [PRIMARY]

GO

ALTER TABLE [dbo].[dbm_db_principal] ADD  CONSTRAINT [DF_dbm_db_principal_updated_at]  DEFAULT (getdate()) FOR [updated_at]
GO

CREATE TABLE [dbo].[dbm_db_principal_audit](
	[record_id] [int] IDENTITY(1,1) NOT NULL,
	[connection_name] [varchar](128) NOT NULL,
	[principal_name] [varchar](128) NOT NULL,
	[source_ip] [varchar](128) NOT NULL,
	[source_host] [varchar](128) NULL,
	[success_logons] [int] NOT NULL,
	[last_success_logon] [datetime] NULL,
	[failed_logons] [int] NOT NULL,
	[last_failed_logon] [datetime] NULL,
	[review_status] [varchar](32) NULL,
	[review_notes] [varchar](4000) NULL,
	[review_date] [datetime] NULL,
	[updated_at] [datetime] NOT NULL,
	[updated_by] [varchar](50) NULL,
 CONSTRAINT [PK_dbm_db_principal_audit] PRIMARY KEY CLUSTERED ([record_id] ASC)
 WITH (PAD_INDEX  = OFF, STATISTICS_NORECOMPUTE  = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS  = ON, ALLOW_PAGE_LOCKS  = ON) 
 ON [PRIMARY]
) ON [PRIMARY]

GO

SET ANSI_PADDING OFF
GO

ALTER TABLE [dbo].[dbm_db_principal_audit]  
WITH CHECK ADD  CONSTRAINT [FK_dbm_db_principal_audit_dbm_db_principal] 
FOREIGN KEY([connection_name], [principal_name])
REFERENCES [dbo].[dbm_db_principal] ([connection_name], [principal_name])
ON DELETE CASCADE
GO

ALTER TABLE [dbo].[dbm_db_principal_audit] CHECK CONSTRAINT [FK_dbm_db_principal_audit_dbm_db_principal]
GO