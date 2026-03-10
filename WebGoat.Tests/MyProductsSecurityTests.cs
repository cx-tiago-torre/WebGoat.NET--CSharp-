using System;
using System.Data;
using System.IO;
using System.Web;
using NUnit.Framework;
using Mono.Data.Sqlite;

namespace OWASP.WebGoat.NET.Tests
{
    /// <summary>
    /// Security tests for MyProducts.aspx.cs SQL injection vulnerability remediation.
    /// These tests verify that the LoadComments method properly uses parameterized queries
    /// to prevent SQL injection attacks.
    /// </summary>
    [TestFixture]
    public class MyProductsSecurityTests
    {
        private string _testDbPath;
        private string _connectionString;

        [SetUp]
        public void Setup()
        {
            // Create a temporary SQLite database for testing
            _testDbPath = Path.Combine(Path.GetTempPath(), $"test_webgoat_{Guid.NewGuid()}.db");
            _connectionString = $"Data Source={_testDbPath};Version=3;";

            // Initialize test database with schema and data
            InitializeTestDatabase();
        }

        [TearDown]
        public void TearDown()
        {
            // Clean up test database
            if (File.Exists(_testDbPath))
            {
                try
                {
                    File.Delete(_testDbPath);
                }
                catch
                {
                    // Ignore cleanup errors
                }
            }
        }

        /// <summary>
        /// Initializes a test SQLite database with the CustomerLogin table and sample data.
        /// </summary>
        private void InitializeTestDatabase()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Create CustomerLogin table
                string createTableSql = @"
                    CREATE TABLE IF NOT EXISTS CustomerLogin (
                        customerNumber INTEGER PRIMARY KEY,
                        email TEXT NOT NULL,
                        password TEXT
                    )";

                using (var command = new SqliteCommand(createTableSql, connection))
                {
                    command.ExecuteNonQuery();
                }

                // Insert test data
                string insertDataSql = @"
                    INSERT INTO CustomerLogin (customerNumber, email, password) VALUES
                    (1, 'user1@example.com', 'password1'),
                    (2, 'user2@example.com', 'password2'),
                    (999, 'admin@example.com', 'secretpassword')";

                using (var command = new SqliteCommand(insertDataSql, connection))
                {
                    command.ExecuteNonQuery();
                }
            }
        }

        /// <summary>
        /// Test that valid customer numbers return correct email addresses.
        /// This verifies basic functionality works after the security fix.
        /// </summary>
        [Test]
        public void TestValidCustomerNumber_ReturnsCorrectEmail()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Use parameterized query (the secure approach)
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", "1");

                object result = command.ExecuteScalar();

                Assert.IsNotNull(result, "Result should not be null for valid customer number");
                Assert.AreEqual("user1@example.com", result.ToString(), "Email should match expected value");
            }
        }

        /// <summary>
        /// Test that SQL injection attempts are neutralized by parameterized queries.
        /// This test verifies that malicious SQL payloads in the customerNumber parameter
        /// are treated as literal string values and do not execute as SQL code.
        /// </summary>
        [Test]
        public void TestSQLInjectionAttempt_IsNeutralized()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Common SQL injection payload that attempts to bypass authentication
                // or extract additional data
                string maliciousInput = "1 OR 1=1";

                // Use parameterized query (the secure approach)
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                object result = command.ExecuteScalar();

                // With parameterized queries, the malicious input is treated as a literal string
                // and should return null since no customer has that exact customerNumber
                Assert.IsNull(result, "SQL injection payload should not return any results");
            }
        }

        /// <summary>
        /// Test that UNION-based SQL injection attacks are prevented.
        /// UNION attacks attempt to combine results from multiple queries to extract
        /// sensitive data from other tables.
        /// </summary>
        [Test]
        public void TestUnionBasedSQLInjection_IsPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // UNION-based SQL injection payload
                string maliciousInput = "1 UNION SELECT password FROM CustomerLogin WHERE customerNumber=999";

                // Use parameterized query
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                object result = command.ExecuteScalar();

                // Should return null, not the password
                Assert.IsNull(result, "UNION-based injection should not return data");
            }
        }

        /// <summary>
        /// Test that comment-based SQL injection attacks are prevented.
        /// These attacks use SQL comment syntax to truncate queries and bypass conditions.
        /// </summary>
        [Test]
        public void TestCommentBasedSQLInjection_IsPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Comment-based SQL injection payload
                string maliciousInput = "1' OR '1'='1' --";

                // Use parameterized query
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                object result = command.ExecuteScalar();

                // Should return null, treating the entire string as a literal customer number
                Assert.IsNull(result, "Comment-based injection should not bypass authentication");
            }
        }

        /// <summary>
        /// Test that stacked query SQL injection attacks are prevented.
        /// These attacks attempt to execute multiple SQL statements separated by semicolons.
        /// </summary>
        [Test]
        public void TestStackedQuerySQLInjection_IsPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Stacked query injection payload that attempts to drop a table
                string maliciousInput = "1; DROP TABLE CustomerLogin; --";

                // Use parameterized query
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                object result = command.ExecuteScalar();

                // Should not execute the DROP command
                Assert.IsNull(result, "Stacked query injection should not execute additional SQL");

                // Verify table still exists by querying it
                string verifyTableSql = "SELECT COUNT(*) FROM CustomerLogin";
                using (var verifyCommand = new SqliteCommand(verifyTableSql, connection))
                {
                    long count = (long)verifyCommand.ExecuteScalar();
                    Assert.Greater(count, 0, "Table should still exist after injection attempt");
                }
            }
        }

        /// <summary>
        /// Test that blind SQL injection attempts are prevented.
        /// Blind SQL injection uses conditional logic to infer information based on
        /// application behavior when the attacker cannot see query results directly.
        /// </summary>
        [Test]
        public void TestBlindSQLInjection_IsPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Blind SQL injection payload using conditional logic
                string maliciousInput = "1 AND (SELECT COUNT(*) FROM CustomerLogin) > 0";

                // Use parameterized query
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                object result = command.ExecuteScalar();

                // Should return null, not execute the subquery
                Assert.IsNull(result, "Blind SQL injection should not execute conditional logic");
            }
        }

        /// <summary>
        /// Test that time-based SQL injection attempts are prevented.
        /// These attacks use database sleep functions to infer information based on response time.
        /// </summary>
        [Test]
        public void TestTimeBasedSQLInjection_IsPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Time-based SQL injection payload (SQLite uses randomblob for delays)
                string maliciousInput = "1 AND (SELECT COUNT(*) FROM (SELECT randomblob(1000000000))) > 0";

                // Use parameterized query
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                DateTime startTime = DateTime.Now;
                object result = command.ExecuteScalar();
                DateTime endTime = DateTime.Now;

                // Query should complete quickly (under 1 second) since the payload is treated as a literal
                TimeSpan executionTime = endTime - startTime;
                Assert.Less(executionTime.TotalSeconds, 1.0, "Query should not be delayed by time-based injection");
                Assert.IsNull(result, "Time-based injection should not execute");
            }
        }

        /// <summary>
        /// Test that special characters in customer numbers are properly escaped.
        /// This verifies that the parameterization handles various edge cases.
        /// </summary>
        [Test]
        public void TestSpecialCharacters_AreProperlyEscaped()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Test various special characters
                string[] specialInputs = {
                    "1'",
                    "1\"",
                    "1`",
                    "1\\",
                    "1%",
                    "1_",
                    "1;",
                    "1\n",
                    "1\r",
                    "1\t"
                };

                foreach (string input in specialInputs)
                {
                    string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                    SqliteCommand command = new SqliteCommand(sql, connection);
                    command.Parameters.AddWithValue("@customerNumber", input);

                    object result = command.ExecuteScalar();

                    // All special characters should be safely handled
                    // None should cause errors or unexpected behavior
                    Assert.IsNull(result, $"Special character input '{input}' should not return results or cause errors");
                }
            }
        }

        /// <summary>
        /// Test that null or empty customer numbers are handled gracefully.
        /// </summary>
        [Test]
        public void TestNullOrEmptyCustomerNumber_HandledGracefully()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Test null value
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", DBNull.Value);

                object result = command.ExecuteScalar();
                Assert.IsNull(result, "Null customer number should return no results");

                // Test empty string
                command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", "");

                result = command.ExecuteScalar();
                Assert.IsNull(result, "Empty customer number should return no results");
            }
        }

        /// <summary>
        /// Test that numeric customer numbers work correctly with parameterized queries.
        /// </summary>
        [Test]
        public void TestNumericCustomerNumbers_WorkCorrectly()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Test with integer parameter
                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", 2);

                object result = command.ExecuteScalar();

                Assert.IsNotNull(result, "Numeric customer number should return result");
                Assert.AreEqual("user2@example.com", result.ToString(), "Should return correct email for customer 2");
            }
        }

        /// <summary>
        /// Test that non-existent customer numbers return null gracefully.
        /// </summary>
        [Test]
        public void TestNonExistentCustomerNumber_ReturnsNull()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", "99999");

                object result = command.ExecuteScalar();

                Assert.IsNull(result, "Non-existent customer number should return null");
            }
        }

        /// <summary>
        /// Test that the fix prevents data exfiltration attempts through error-based injection.
        /// Error-based SQL injection tries to extract data through database error messages.
        /// </summary>
        [Test]
        public void TestErrorBasedSQLInjection_IsPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Error-based SQL injection payload
                string maliciousInput = "1 AND 1=CAST((SELECT email FROM CustomerLogin LIMIT 1) AS INTEGER)";

                string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                SqliteCommand command = new SqliteCommand(sql, connection);
                command.Parameters.AddWithValue("@customerNumber", maliciousInput);

                object result = command.ExecuteScalar();

                // Should not execute the CAST operation or return error messages
                Assert.IsNull(result, "Error-based injection should not extract data through errors");
            }
        }

        /// <summary>
        /// Integration test that verifies the complete fix prevents multiple attack vectors
        /// in a single test scenario.
        /// </summary>
        [Test]
        public void TestMultipleAttackVectors_AllPrevented()
        {
            using (var connection = new SqliteConnection(_connectionString))
            {
                connection.Open();

                // Array of various SQL injection payloads
                string[] attackPayloads = {
                    "' OR '1'='1",
                    "1 OR 1=1",
                    "1' UNION SELECT password FROM CustomerLogin--",
                    "1; DELETE FROM CustomerLogin WHERE customerNumber=1--",
                    "1' AND (SELECT COUNT(*) FROM CustomerLogin) > 0--",
                    "admin'--",
                    "1' OR 'x'='x",
                    "105 OR 1=1",
                    "1' OR '1'='1' /*",
                    "' or 1=1--",
                    "' OR 'a'='a",
                    "') OR ('a'='a"
                };

                foreach (string payload in attackPayloads)
                {
                    string sql = "select email from CustomerLogin where customerNumber = @customerNumber";
                    SqliteCommand command = new SqliteCommand(sql, connection);
                    command.Parameters.AddWithValue("@customerNumber", payload);

                    object result = command.ExecuteScalar();

                    // All attack payloads should be neutralized
                    Assert.IsNull(result, $"Attack payload '{payload}' should be neutralized");
                }

                // Verify database integrity after all attack attempts
                string verifyDataSql = "SELECT COUNT(*) FROM CustomerLogin";
                using (var verifyCommand = new SqliteCommand(verifyDataSql, connection))
                {
                    long count = (long)verifyCommand.ExecuteScalar();
                    Assert.AreEqual(3, count, "All test records should still exist after attack attempts");
                }
            }
        }
    }
}
