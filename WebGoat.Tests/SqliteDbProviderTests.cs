using System;
using System.Data;
using NUnit.Framework;
using Mono.Data.Sqlite;
using OWASP.WebGoat.NET.App_Code.DB;
using OWASP.WebGoat.NET.App_Code;
using System.IO;

namespace OWASP.WebGoat.NET.Tests
{
    /// <summary>
    /// Security tests for SqliteDbProvider.GetEmailByCustomerNumber method
    /// These tests verify that SQL injection vulnerabilities have been properly remediated
    /// </summary>
    [TestFixture]
    public class SqliteDbProviderTests
    {
        private SqliteDbProvider _dbProvider;
        private string _testDbPath;
        private string _connectionString;

        [SetUp]
        public void Setup()
        {
            // Create a temporary test database
            _testDbPath = Path.Combine(Path.GetTempPath(), $"test_webgoat_{Guid.NewGuid()}.db");
            _connectionString = $"Data Source={_testDbPath};Version=3";

            // Initialize test database with schema and data
            InitializeTestDatabase();

            // Create a mock ConfigFile for the provider
            var configFile = new TestConfigFile(_testDbPath);
            _dbProvider = new SqliteDbProvider(configFile);
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

        private void InitializeTestDatabase()
        {
            using (SqliteConnection conn = new SqliteConnection(_connectionString))
            {
                conn.Open();

                // Create CustomerLogin table
                using (SqliteCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
                        CREATE TABLE IF NOT EXISTS CustomerLogin (
                            customerNumber INTEGER PRIMARY KEY,
                            email TEXT NOT NULL,
                            password TEXT NOT NULL
                        )";
                    cmd.ExecuteNonQuery();
                }

                // Insert test data
                using (SqliteCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = @"
                        INSERT INTO CustomerLogin (customerNumber, email, password)
                        VALUES
                            (103, 'test1@example.com', 'password1'),
                            (112, 'test2@example.com', 'password2'),
                            (114, 'test3@example.com', 'password3'),
                            (119, 'admin@example.com', 'adminpass')";
                    cmd.ExecuteNonQuery();
                }
            }
        }

        #region Positive Test Cases - Valid Functionality

        [Test]
        [Category("Security")]
        [Category("Positive")]
        public void GetEmailByCustomerNumber_ValidCustomerNumber_ReturnsCorrectEmail()
        {
            // Arrange
            string customerNumber = "103";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(customerNumber);

            // Assert
            Assert.AreEqual("test1@example.com", result,
                "Should return the correct email for a valid customer number");
        }

        [Test]
        [Category("Security")]
        [Category("Positive")]
        public void GetEmailByCustomerNumber_AnotherValidCustomerNumber_ReturnsCorrectEmail()
        {
            // Arrange
            string customerNumber = "119";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(customerNumber);

            // Assert
            Assert.AreEqual("admin@example.com", result,
                "Should return the correct email for another valid customer number");
        }

        [Test]
        [Category("Security")]
        [Category("Positive")]
        public void GetEmailByCustomerNumber_NonExistentCustomerNumber_ReturnsEmptyString()
        {
            // Arrange
            string customerNumber = "999";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(customerNumber);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result),
                "Should return empty string for non-existent customer number");
        }

        #endregion

        #region Negative Test Cases - SQL Injection Attack Prevention

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_SQLInjectionWithOR_DoesNotBypassQuery()
        {
            // Arrange - Classic SQL injection with OR clause
            string maliciousInput = "103 OR 1=1";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            // With parameterized query, this should return empty or error, not all records
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should not return data for SQL injection attempt with OR clause");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_SQLInjectionWithUnion_DoesNotExecuteUnion()
        {
            // Arrange - UNION-based SQL injection
            string maliciousInput = "103 UNION SELECT password FROM CustomerLogin WHERE customerNumber=119";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            // Should not return password data through UNION
            Assert.IsFalse(result.Contains("adminpass"),
                "Should not execute UNION clause in SQL injection attempt");
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should return empty or error for UNION injection attempt");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_SQLInjectionWithComment_DoesNotIgnoreWhereClause()
        {
            // Arrange - SQL injection with comment to bypass WHERE clause
            string maliciousInput = "103 OR 1=1--";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should not bypass WHERE clause with comment injection");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_SQLInjectionWithSemicolon_DoesNotExecuteSecondQuery()
        {
            // Arrange - Stacked query injection attempt
            string maliciousInput = "103; DROP TABLE CustomerLogin--";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should not execute stacked queries");

            // Verify table still exists
            using (SqliteConnection conn = new SqliteConnection(_connectionString))
            {
                conn.Open();
                using (SqliteCommand cmd = conn.CreateCommand())
                {
                    cmd.CommandText = "SELECT COUNT(*) FROM CustomerLogin";
                    int count = Convert.ToInt32(cmd.ExecuteScalar());
                    Assert.Greater(count, 0, "CustomerLogin table should still exist and contain data");
                }
            }
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_SQLInjectionWithSubquery_DoesNotExecuteSubquery()
        {
            // Arrange - Subquery injection
            string maliciousInput = "(SELECT customerNumber FROM CustomerLogin WHERE email='admin@example.com')";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should not execute subquery injection");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_SQLInjectionWithQuotes_ProperlySanitizesInput()
        {
            // Arrange - Quote escape injection
            string maliciousInput = "103' OR 'a'='a";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should properly sanitize single quotes in input");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_BlindSQLInjection_DoesNotRevealDatabaseStructure()
        {
            // Arrange - Boolean-based blind SQL injection
            string maliciousInput = "103 AND 1=1";

            // Act
            string result1 = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            maliciousInput = "103 AND 1=2";
            string result2 = _dbProvider.GetEmailByCustomerNumber(maliciousInput);

            // Assert
            // Both should behave the same (return empty or error), not reveal boolean conditions
            Assert.IsTrue(string.IsNullOrEmpty(result1) || result1.Contains("Error"),
                "Should not reveal database structure through boolean injection (1=1)");
            Assert.IsTrue(string.IsNullOrEmpty(result2) || result2.Contains("Error"),
                "Should not reveal database structure through boolean injection (1=2)");
        }

        [Test]
        [Category("Security")]
        [Category("SQLInjection")]
        public void GetEmailByCustomerNumber_TimingAttackWithBenchmark_DoesNotExecute()
        {
            // Arrange - Time-based blind SQL injection (SQLite doesn't have BENCHMARK but this tests the concept)
            string maliciousInput = "103 OR SLEEP(5)--";

            // Act
            DateTime startTime = DateTime.Now;
            string result = _dbProvider.GetEmailByCustomerNumber(maliciousInput);
            TimeSpan elapsed = DateTime.Now - startTime;

            // Assert
            Assert.Less(elapsed.TotalSeconds, 2,
                "Query should not execute time-delay functions");
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should not execute timing attack payload");
        }

        #endregion

        #region Edge Cases

        [Test]
        [Category("Security")]
        [Category("EdgeCase")]
        public void GetEmailByCustomerNumber_EmptyString_HandlesGracefully()
        {
            // Arrange
            string customerNumber = "";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(customerNumber);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should handle empty string gracefully");
        }

        [Test]
        [Category("Security")]
        [Category("EdgeCase")]
        public void GetEmailByCustomerNumber_WhitespaceOnly_HandlesGracefully()
        {
            // Arrange
            string customerNumber = "   ";

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(customerNumber);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should handle whitespace-only input gracefully");
        }

        [Test]
        [Category("Security")]
        [Category("EdgeCase")]
        public void GetEmailByCustomerNumber_SpecialCharacters_HandlesGracefully()
        {
            // Arrange - Various special characters that could cause issues
            string[] specialInputs = {
                "103<script>alert('xss')</script>",
                "103%00",
                "103\0",
                "103\n\r",
                "103\\",
                "103\"\"",
                "103``"
            };

            // Act & Assert
            foreach (string input in specialInputs)
            {
                string result = _dbProvider.GetEmailByCustomerNumber(input);
                Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                    $"Should handle special characters gracefully: {input}");
            }
        }

        [Test]
        [Category("Security")]
        [Category("EdgeCase")]
        public void GetEmailByCustomerNumber_VeryLongInput_HandlesGracefully()
        {
            // Arrange - Test with very long input
            string customerNumber = new string('1', 10000);

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(customerNumber);

            // Assert
            Assert.IsTrue(string.IsNullOrEmpty(result) || result.Contains("Error"),
                "Should handle very long input gracefully");
        }

        #endregion

        #region Integration Tests

        [Test]
        [Category("Security")]
        [Category("Integration")]
        public void GetEmailByCustomerNumber_CalledFromUI_ProperlyHandlesTrimmedInput()
        {
            // Arrange - Simulating the UI layer call from SQLInjectionDiscovery.aspx.cs
            // The UI takes first 3 characters via Substring(0, 3)
            string fullInput = "103test";
            string trimmedInput = fullInput.Substring(0, 3);

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(trimmedInput);

            // Assert
            Assert.AreEqual("test1@example.com", result,
                "Should work correctly with trimmed input from UI layer");
        }

        [Test]
        [Category("Security")]
        [Category("Integration")]
        public void GetEmailByCustomerNumber_CalledFromUI_BlocksInjectionAfterTrim()
        {
            // Arrange - Even if attacker tries injection in first 3 chars
            string maliciousFullInput = "103 OR 1=1--extra";
            string trimmedInput = maliciousFullInput.Substring(0, 3);

            // Act
            string result = _dbProvider.GetEmailByCustomerNumber(trimmedInput);

            // Assert
            // The trim to 3 chars gives "103" which is valid
            Assert.AreEqual("test1@example.com", result,
                "With UI trimming, '103' should return valid result");
        }

        #endregion

        /// <summary>
        /// Test helper class to provide configuration for SqliteDbProvider
        /// </summary>
        private class TestConfigFile : ConfigFile
        {
            private readonly string _dbPath;

            public TestConfigFile(string dbPath) : base("")
            {
                _dbPath = dbPath;
            }

            public override string Get(string key)
            {
                if (key == DbConstants.KEY_FILE_NAME)
                    return _dbPath;
                if (key == DbConstants.KEY_CLIENT_EXEC)
                    return "";
                return "";
            }
        }
    }
}
