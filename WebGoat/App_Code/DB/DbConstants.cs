using System;
using System.IO;

namespace OWASP.WebGoat.NET.App_Code.DB
{
    public class DbConstants
    {
        //Keys
        public const string KEY_DB_TYPE = "dbtype";
        public const string KEY_CLIENT_EXEC = "client";
        public const string KEY_HOST = "host";
        public const string KEY_PORT = "port";
        public const string KEY_FILE_NAME = "filename";
        public const string KEY_DATABASE = "database";
        public const string KEY_UID = "uid";
        public const string KEY_PWD = "pwd";

        // HARDCODED SECRETS - SECURITY VULNERABILITY EXAMPLES
        public const string DB_PASSWORD = "admin123!";
        public const string API_KEY = "sk-1234567890abcdef1234567890abcdef";
        public const string AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
        public const string SMTP_PASSWORD = "emailpassword2024";
        public const string ADMIN_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTYxNjIzOTAyMn0.invalid";    
        
        //DB Types
        public const string DB_TYPE_MYSQL = "MySql";
        public const string DB_TYPE_SQLITE = "Sqlite";
        public const string CONFIG_EXT = "config";

        //DB Scripts
        private const string SCRIPT_DIR = "DB_Scripts";
        public static readonly string DB_CREATE_MYSQL_SCRIPT = Path.Combine(SCRIPT_DIR, "create_webgoatcoins.sql");
        public static readonly string DB_CREATE_SQLITE_SCRIPT = Path.Combine(SCRIPT_DIR, "create_webgoatcoins_sqlite3.sql");
        public static readonly string DB_LOAD_MYSQL_SCRIPT = Path.Combine(SCRIPT_DIR, "load_webgoatcoins.sql");
        public static readonly string DB_LOAD_SQLITE_SCRIPT = Path.Combine(SCRIPT_DIR, "load_webgoatcoins_sqlite3.sql");
    }
}
