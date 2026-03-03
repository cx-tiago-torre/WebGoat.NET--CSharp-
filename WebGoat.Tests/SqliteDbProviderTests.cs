using System;
using System.Data;
using System.IO;
using Mono.Data.Sqlite;
using NUnit.Framework;
using OWASP.WebGoat.NET.App_Code;
using OWASP.WebGoat.NET.App_Code.DB;

namespace OWASP.WebGoat.NET.Tests
{
    /// <summary>
    /// Test suite for SQL injection vulnerability remediation in SqliteDbProvider.GetPasswordByEmail
    /// These tests verify that the parameterized query implementation prevents SQL injection attacks
    /// </summary>
    [TestFixture]
    public class SqliteDbProviderTests
    {
        private SqliteDbProvider _dbProvider;
        private string _testDbPath;
        private string _connectionString;

        [SetUp]
        public void SetUp()
        {
            // Create a temporary test database
            _testDbPath = Path.Combine(Path.GetTempPath(), $"test_webgoat_{Guid.NewGuid()}.db");
            _connectionString = $"Data Source={_testDbPath};Version=3";

            // Initialize the database with test data
            InitializeTestDatabase();

            // Create the DB provider using a mock config
            var configFile = new TestConfigFile(_testDbPath);
            _dbProvider = new SqliteDbProvider(configFile);
        }

        [TearDown]
        public void TearDown()
        {
            // Clean up test database
            if (File.Exists(_testDbPath))
            {
                File.Delete(_testDbPath);
            }
        }

        private void InitializeTestDatabase()
        {
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Create the CustomerLogin table
                string createTableSql = @"
                    CREATE TABLE CustomerLogin (
                        customerNumber INTEGER PRIMARY KEY,
                        email TEXT NOT NULL,
                        password TEXT NOT NULL,
                        question_id INTEGER,
                        answer TEXT
                    )";

                using (SqliteCommand command = new SqliteCommand(createTableSql, connection))
                {
                    command.ExecuteNonQuery();
                }

                // Insert test data with encoded passwords
                string insertSql = @"
                    INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer)
                    VALUES
                    (1, 'test@example.com', @password1, 1, 'answer1'),
                    (2, 'admin@example.com', @password2, 1, 'answer2'),
                    (3, 'user@example.com', @password3, 1, 'answer3')";

                using (SqliteCommand command = new SqliteCommand(insertSql, connection))
                {
                    // Use encoded passwords similar to the application
                    command.Parameters.AddWithValue("@password1", Encoder.Encode("password123"));
                    command.Parameters.AddWithValue("@password2", Encoder.Encode("admin123"));
                    command.Parameters.AddWithValue("@password3", Encoder.Encode("user123"));
                    command.ExecuteNonQuery();
                }
            }
        }

        /// <summary>
        /// Test that GetPasswordByEmail returns the correct password for a valid email
        /// This is the positive test case - verifying normal functionality works
        /// </summary>
        [Test]
        public void GetPasswordByEmail_ValidEmail_ReturnsCorrectPassword()
        {
            // Arrange
            string email = "test@example.com";
            string expectedPassword = "password123";

            // Act
            string result = _dbProvider.GetPasswordByEmail(email);

            // Assert
            Assert.AreEqual(expectedPassword, result, "Should return the correct password for valid email");
        }

        /// <summary>
        /// Test that GetPasswordByEmail returns error message for non-existent email
        /// </summary>
        [Test]
        public void GetPasswordByEmail_NonExistentEmail_ReturnsErrorMessage()
        {
            // Arrange
            string email = "nonexistent@example.com";

            // Act
            string result = _dbProvider.GetPasswordByEmail(email);

            // Assert
            Assert.AreEqual("Email Address Not Found!", result, "Should return error message for non-existent email");
        }

        /// <summary>
        /// SECURITY TEST: Verify that SQL injection via single quote is prevented
        /// Attack vector: ' OR '1'='1
        /// This is the most common SQL injection attack pattern
        /// </summary>
        [Test]
        public void GetPasswordByEmail_SQLInjectionWithSingleQuote_DoesNotExposeData()
        {
            // Arrange - Classic SQL injection attempt
            string maliciousEmail = "' OR '1'='1";

            // Act
            string result = _dbProvider.GetPasswordByEmail(maliciousEmail);

            // Assert
            // With parameterized queries, this should NOT return any password
            // It should either return error message or empty result
            Assert.AreNotEqual("password123", result, "Should not return any valid password for SQL injection attempt");
            Assert.AreNotEqual("admin123", result, "Should not return any valid password for SQL injection attempt");
            Assert.AreNotEqual("user123", result, "Should not return any valid password for SQL injection attempt");
        }

        /// <summary>
        /// SECURITY TEST: Verify that SQL injection with UNION SELECT is prevented
        /// Attack vector: test@example.com' UNION SELECT * FROM CustomerLogin--
        /// </summary>
        [Test]
        public void GetPasswordByEmail_SQLInjectionWithUnion_DoesNotExposeData()
        {
            // Arrange - UNION-based SQL injection attempt
            string maliciousEmail = "test@example.com' UNION SELECT * FROM CustomerLogin--";

            // Act
            string result = _dbProvider.GetPasswordByEmail(maliciousEmail);

            // Assert
            // Should not find any email with this exact string (including the SQL)
            Assert.AreEqual("Email Address Not Found!", result, "Should not execute injected UNION query");
        }

        /// <summary>
        /// SECURITY TEST: Verify that SQL injection with comment injection is prevented
        /// Attack vector: admin@example.com'--
        /// </summary>
        [Test]
        public void GetPasswordByEmail_SQLInjectionWithComment_DoesNotBypassValidation()
        {
            // Arrange - Comment-based SQL injection attempt
            string maliciousEmail = "admin@example.com'--";

            // Act
            string result = _dbProvider.GetPasswordByEmail(maliciousEmail);

            // Assert
            // Should not find any email with this exact string
            Assert.AreNotEqual("admin123", result, "Should not execute query with injected comment");
        }

        /// <summary>
        /// SECURITY TEST: Verify that SQL injection with OR condition is prevented
        /// Attack vector: ' OR 1=1--
        /// </summary>
        [Test]
        public void GetPasswordByEmail_SQLInjectionWithORCondition_DoesNotExposeData()
        {
            // Arrange - OR-based SQL injection attempt
            string maliciousEmail = "' OR 1=1--";

            // Act
            string result = _dbProvider.GetPasswordByEmail(maliciousEmail);

            // Assert
            Assert.AreNotEqual("password123", result, "Should not return password for OR injection");
            Assert.AreNotEqual("admin123", result, "Should not return password for OR injection");
            Assert.AreNotEqual("user123", result, "Should not return password for OR injection");
        }

        /// <summary>
        /// SECURITY TEST: Verify that SQL injection with DROP TABLE is prevented
        /// Attack vector: '; DROP TABLE CustomerLogin--
        /// </summary>
        [Test]
        public void GetPasswordByEmail_SQLInjectionWithDropTable_DoesNotExecuteDestructiveCommand()
        {
            // Arrange - Destructive SQL injection attempt
            string maliciousEmail = "'; DROP TABLE CustomerLogin--";

            // Act
            string result = _dbProvider.GetPasswordByEmail(maliciousEmail);

            // Assert
            // The table should still exist after this call
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string checkTableSql = "SELECT name FROM sqlite_master WHERE type='table' AND name='CustomerLogin'";
                using (SqliteCommand command = new SqliteCommand(checkTableSql, connection))
                {
                    var tableName = command.ExecuteScalar();
                    Assert.IsNotNull(tableName, "CustomerLogin table should still exist - DROP TABLE should not execute");
                }
            }
        }

        /// <summary>
        /// SECURITY TEST: Verify that SQL injection with special characters is handled safely
        /// Tests various special SQL characters that could be used in injection attacks
        /// </summary>
        [Test]
        public void GetPasswordByEmail_SpecialCharactersInEmail_HandledSafely()
        {
            // Arrange - Test multiple special characters
            string[] specialCharEmails = new[]
            {
                "test';--",
                "test\"@example.com",
                "test@example.com'; DELETE FROM CustomerLogin WHERE '1'='1",
                "test@example.com' AND 1=0 UNION ALL SELECT password FROM CustomerLogin--"
            };

            // Act & Assert
            foreach (string email in specialCharEmails)
            {
                string result = _dbProvider.GetPasswordByEmail(email);

                // None of these should return valid passwords
                Assert.AreNotEqual("password123", result, $"Email '{email}' should not expose password");
                Assert.AreNotEqual("admin123", result, $"Email '{email}' should not expose password");
                Assert.AreNotEqual("user123", result, $"Email '{email}' should not expose password");
            }
        }

        /// <summary>
        /// SECURITY TEST: Verify that blind SQL injection time-based attacks are prevented
        /// Attack vector: ' OR SLEEP(5)--
        /// </summary>
        [Test]
        public void GetPasswordByEmail_BlindSQLInjectionAttempt_ExecutesQuickly()
        {
            // Arrange
            string maliciousEmail = "' OR SLEEP(5)--";
            DateTime startTime = DateTime.Now;

            // Act
            string result = _dbProvider.GetPasswordByEmail(maliciousEmail);
            TimeSpan elapsed = DateTime.Now - startTime;

            // Assert
            // Query should complete quickly (under 2 seconds) - injected SLEEP should not execute
            Assert.IsTrue(elapsed.TotalSeconds < 2, "Query should not execute SLEEP command");
        }

        /// <summary>
        /// Test that email with legitimate special characters (but not SQL injection) works correctly
        /// This ensures the fix doesn't break legitimate use cases
        /// </summary>
        [Test]
        public void GetPasswordByEmail_LegitimateEmailWithPlus_WorksCorrectly()
        {
            // Arrange - Insert a legitimate email with + character
            using (SqliteConnection connection = new SqliteConnection(_connectionString))
            {
                connection.Open();
                string insertSql = "INSERT INTO CustomerLogin (customerNumber, email, password, question_id, answer) VALUES (4, @email, @password, 1, 'answer4')";
                using (SqliteCommand command = new SqliteCommand(insertSql, connection))
                {
                    command.Parameters.AddWithValue("@email", "test+tag@example.com");
                    command.Parameters.AddWithValue("@password", Encoder.Encode("test123"));
                    command.ExecuteNonQuery();
                }
            }

            // Act
            string result = _dbProvider.GetPasswordByEmail("test+tag@example.com");

            // Assert
            Assert.AreEqual("test123", result, "Should handle legitimate special characters in email");
        }

        /// <summary>
        /// SECURITY TEST: Verify that case sensitivity in email doesn't bypass security
        /// Some SQL injection attacks rely on case variations
        /// </summary>
        [Test]
        public void GetPasswordByEmail_CaseVariationsInEmail_HandledConsistently()
        {
            // Arrange
            string email = "TEST@EXAMPLE.COM";

            // Act
            string result = _dbProvider.GetPasswordByEmail(email);

            // Assert
            // SQLite is case-insensitive for LIKE but case-sensitive for =
            // Result should be consistent (either found or not found, but not expose injection)
            Assert.IsTrue(result == "Email Address Not Found!" || result == "password123",
                "Case variations should be handled consistently without exposing injection vectors");
        }
    }

    /// <summary>
    /// Test implementation of ConfigFile for unit testing
    /// </summary>
    internal class TestConfigFile : ConfigFile
    {
        private readonly string _dbPath;

        public TestConfigFile(string dbPath)
        {
            _dbPath = dbPath;
        }

        public override string Get(string key)
        {
            if (key == DbConstants.KEY_FILE_NAME)
            {
                return _dbPath;
            }
            if (key == DbConstants.KEY_CLIENT_EXEC)
            {
                return "sqlite3"; // Default SQLite client
            }
            return string.Empty;
        }
    }
}
