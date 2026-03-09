using System;
using System.IO;
using System.Text;
using System.Web;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Reflection;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;
using ICSharpCode.SharpZipLib.GZip;
using ICSharpCode.SharpZipLib.Zip;
using ICSharpCode.SharpZipLib.Tar;
using ICSharpCode.SharpZipLib.Core;
using Mono.Data.Sqlite;

namespace OWASP.WebGoat.NET
{
    /// <summary>
    /// Utility class for compression operations using SharpZipLib.
    /// 
    /// CVE-2021-32840 specifically affects EXTRACTION methods (ZipFile.ExtractAll, TarArchive.ExtractContents)
    /// which allow path traversal during extraction. This class does NOT use any extraction methods.
    /// </summary>
    public class CompressionUtility
    {
        /// <summary>
        /// Compresses a string using GZip compression (NOT VULNERABLE).
        /// This method only uses GZipOutputStream for compression, not extraction.
        /// </summary>
        /// <param name="input">String to compress</param>
        /// <returns>Compressed byte array</returns>
        public static byte[] CompressStringToGZip(string input)
        {
            if (string.IsNullOrEmpty(input))
                return null;

            try
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(input);
                
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (GZipOutputStream gzipStream = new GZipOutputStream(outputStream))
                    {
                        gzipStream.Write(inputBytes, 0, inputBytes.Length);
                        gzipStream.Finish();
                    }
                    return outputStream.ToArray();
                }
            }
            catch (ArgumentException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Invalid argument in compression: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                System.Diagnostics.Debug.WriteLine($"IO error during compression: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Decompresses GZip data to string (NOT VULNERABLE).
        /// This is in-memory decompression, not file extraction.
        /// </summary>
        /// <param name="compressedData">Compressed byte array</param>
        /// <returns>Decompressed string</returns>
        public static string DecompressGZipToString(byte[] compressedData)
        {
            if (compressedData == null || compressedData.Length == 0)
                return null;

            try
            {
                using (MemoryStream inputStream = new MemoryStream(compressedData))
                using (GZipInputStream gzipStream = new GZipInputStream(inputStream))
                using (MemoryStream outputStream = new MemoryStream())
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = gzipStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        outputStream.Write(buffer, 0, bytesRead);
                    }
                    return Encoding.UTF8.GetString(outputStream.ToArray());
                }
            }
            catch (ICSharpCode.SharpZipLib.GZip.GZipException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Invalid GZip data: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                System.Diagnostics.Debug.WriteLine($"IO error during decompression: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates a zip archive from text content (NOT VULNERABLE).
        /// This method creates archives using ZipOutputStream, which is not affected by CVE-2021-32840.
        /// The vulnerability only affects extraction operations.
        /// </summary>
        /// <param name="fileName">Name of the file in the archive</param>
        /// <param name="content">Content to add to the archive</param>
        /// <returns>Byte array containing the zip archive</returns>
        public static byte[] CreateZipArchive(string fileName, string content)
        {
            try
            {
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (ZipOutputStream zipStream = new ZipOutputStream(outputStream))
                    {
                        zipStream.SetLevel(9); // 0-9, 9 being the highest compression
                        
                        ZipEntry entry = new ZipEntry(fileName);
                        entry.DateTime = DateTime.Now;
                        
                        zipStream.PutNextEntry(entry);
                        
                        byte[] contentBytes = Encoding.UTF8.GetBytes(content);
                        zipStream.Write(contentBytes, 0, contentBytes.Length);
                        
                        zipStream.CloseEntry();
                        zipStream.Finish();
                    }
                    return outputStream.ToArray();
                }
            }
            catch (ArgumentException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Invalid argument creating zip archive: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                System.Diagnostics.Debug.WriteLine($"IO error creating zip archive: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Creates a TAR archive from text content (NOT VULNERABLE).
        /// This method creates archives using TarOutputStream, not extraction.
        /// CVE-2021-32840 affects TarArchive.ExtractContents(), which is not used here.
        /// </summary>
        /// <param name="fileName">Name of the file in the archive</param>
        /// <param name="content">Content to add to the archive</param>
        /// <returns>Byte array containing the tar archive</returns>
        public static byte[] CreateTarArchive(string fileName, string content)
        {
            try
            {
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (TarOutputStream tarStream = new TarOutputStream(outputStream))
                    {
                        byte[] contentBytes = Encoding.UTF8.GetBytes(content);
                        
                        TarEntry entry = TarEntry.CreateTarEntry(fileName);
                        entry.Size = contentBytes.Length;
                        entry.ModTime = DateTime.Now;
                        
                        tarStream.PutNextEntry(entry);
                        tarStream.Write(contentBytes, 0, contentBytes.Length);
                        tarStream.CloseEntry();
                        tarStream.Finish();
                    }
                    return outputStream.ToArray();
                }
            }
            catch (ArgumentException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Invalid argument creating tar archive: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                System.Diagnostics.Debug.WriteLine($"IO error creating tar archive: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Compresses data using Deflate algorithm (NOT VULNERABLE).
        /// In-memory stream compression is not affected by the path traversal vulnerability.
        /// </summary>
        /// <param name="input">Data to compress</param>
        /// <returns>Compressed byte array</returns>
        public static byte[] DeflateCompress(byte[] input)
        {
            if (input == null || input.Length == 0)
                return null;

            try
            {
                using (MemoryStream outputStream = new MemoryStream())
                {
                    using (ICSharpCode.SharpZipLib.Zip.Compression.Streams.DeflaterOutputStream deflateStream = 
                        new ICSharpCode.SharpZipLib.Zip.Compression.Streams.DeflaterOutputStream(outputStream))
                    {
                        deflateStream.Write(input, 0, input.Length);
                        deflateStream.Finish();
                    }
                    return outputStream.ToArray();
                }
            }
            catch (ArgumentException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Invalid argument in deflate compression: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                System.Diagnostics.Debug.WriteLine($"IO error during deflate compression: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Decompresses data using Deflate algorithm (NOT VULNERABLE).
        /// In-memory stream decompression is not affected by the path traversal vulnerability.
        /// </summary>
        /// <param name="compressedData">Compressed data</param>
        /// <returns>Decompressed byte array</returns>
        public static byte[] DeflateDecompress(byte[] compressedData)
        {
            if (compressedData == null || compressedData.Length == 0)
                return null;

            try
            {
                using (MemoryStream inputStream = new MemoryStream(compressedData))
                using (ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream inflateStream = 
                    new ICSharpCode.SharpZipLib.Zip.Compression.Streams.InflaterInputStream(inputStream))
                using (MemoryStream outputStream = new MemoryStream())
                {
                    byte[] buffer = new byte[4096];
                    int bytesRead;
                    while ((bytesRead = inflateStream.Read(buffer, 0, buffer.Length)) > 0)
                    {
                        outputStream.Write(buffer, 0, bytesRead);
                    }
                    return outputStream.ToArray();
                }
            }
            catch (ICSharpCode.SharpZipLib.SharpZipBaseException ex)
            {
                System.Diagnostics.Debug.WriteLine($"Invalid compressed data: {ex.Message}");
                throw;
            }
            catch (IOException ex)
            {
                System.Diagnostics.Debug.WriteLine($"IO error during deflate decompression: {ex.Message}");
                throw;
            }
        }

        // ========== STORED XSS DEMONSTRATION METHODS ==========
        
        /// <summary>
        /// VULNERABLE: Generates HTML with user comment without proper encoding (EXPLOITABLE STORED XSS).
        /// This method is vulnerable to stored XSS because it directly concatenates user input
        /// into HTML without any encoding or sanitization. An attacker can inject malicious scripts.
        /// Example payload: <script>alert('XSS')</script>
        /// </summary>
        /// <param name="userName">User name</param>
        /// <param name="comment">User comment (untrusted input)</param>
        /// <returns>HTML string with embedded user comment (VULNERABLE)</returns>
        public static string GenerateCommentHtmlVulnerable(string userName, string comment)
        {
            // VULNERABILITY: Direct concatenation without encoding
            // This allows XSS attacks through the comment parameter
            string html = "<div class='user-comment'>" +
                         "<strong>" + userName + "</strong> wrote:" +
                         "<p>" + comment + "</p>" +  // EXPLOITABLE: No encoding here!
                         "</div>";
            
            return html;
        }

        // ========== SQL INJECTION PATTERN - NOT EXPLOITABLE ==========
        public static string BuildSearchQueryForLogging(string searchTerm, string category)
        {
            // SAST will flag this as SQL Injection due to concatenation pattern
            // But this query string is NEVER executed - it's only logged for analytics
            string queryString = "SELECT * FROM Products WHERE Category = '" + category + 
                               "' AND Name LIKE '%" + searchTerm + "%'";
            
            // This would typically be logged to a file or analytics system
            // NOT executed against a database
            LogSearchQuery(queryString);
            
            return queryString;
        }
        
        private static void LogSearchQuery(string query)
        {
            // Just logging for analytics - no database execution
            System.Diagnostics.Debug.WriteLine("Search query (for analytics): " + query);
        }

        // ========== HARD-CODED CREDENTIALS - NOT EXPLOITABLE ==========
        public static class PasswordComplexityExamples
        {
            // SAST will flag these as hard-coded passwords
            // But they are NOT actual credentials - just UI examples
            
            /// <summary>
            /// Example of a WEAK password shown to users (NOT A REAL CREDENTIAL)
            /// </summary>
            public const string ExampleWeakPassword = "password123";
            
            /// <summary>
            /// Generates password strength indicator HTML with example passwords.
            /// These hard-coded strings are display-only and NOT used for authentication.
            /// </summary>
            /// <returns>HTML showing password examples</returns>
            public static string GetPasswordStrengthExamples()
            {
                // SAST may flag this due to "password" strings
                // But this is NOT exploitable - it's just UI guidance
                return "<div class='password-examples'>" +
                       "<p>Weak: " + ExampleWeakPassword + "</p>" +
                       "<p>Strong: " + ExampleStrongPassword + "</p>" +
                       "</div>";
            }
        }

        // ========== COMMAND INJECTION - EXPLOITABLE ==========
        
        /// <summary>
        /// VULNERABLE: Executes system commands with user input (EXPLOITABLE COMMAND INJECTION).
        /// This method directly passes user input to command execution without proper validation
        /// or sanitization. An attacker can inject additional commands using shell metacharacters.
        /// Example exploit: fileName = "file.txt & del /Q *.*" or "file.txt; rm -rf /"
        /// </summary>
        /// <param name="fileName">File name from user input (UNTRUSTED)</param>
        /// <returns>Process output</returns>
        public static string ExecuteFileCommand(string fileName)
        {
            // VULNERABILITY: Direct concatenation of user input into command
            // Attacker can use shell metacharacters like &, |, ;, &&, ||, `, $(), etc.
            string command = "cmd.exe";
            string arguments = "/c type " + fileName;  // EXPLOITABLE: No input validation!
            
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = command,
                    Arguments = arguments,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                
                using (Process process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    return output;
                }
            }
            catch (Exception)
            {
                // IMPROPER EXCEPTION HANDLING #1: Empty catch block - swallows all exceptions
                // This hides errors and makes debugging impossible
            }
            
            return string.Empty;
        }

        // ========== INSECURE DESERIALIZATION - EXPLOITABLE ==========
        
        /// <summary>
        /// VULNERABLE: Deserializes untrusted data without type restrictions (EXPLOITABLE DESERIALIZATION).
        /// This method uses BinaryFormatter to deserialize user-controlled data, which is
        /// extremely dangerous. Attackers can craft malicious serialized objects that execute
        /// arbitrary code during deserialization (gadget chains like ysoserial.net).
        /// This can lead to Remote Code Execution (RCE).
        /// </summary>
        /// <param name="serializedData">Serialized data from untrusted source</param>
        /// <returns>Deserialized object</returns>
        public static object DeserializeUntrustedData(byte[] serializedData)
        {
            // VULNERABILITY: BinaryFormatter is inherently unsafe with untrusted data
            // It can execute arbitrary code through gadget chains
            BinaryFormatter formatter = new BinaryFormatter();
            
            try
            {
                using (MemoryStream stream = new MemoryStream(serializedData))
                {
                    // EXPLOITABLE: No type validation or restrictions
                    // Attacker can provide malicious serialized payload
                    object deserializedObject = formatter.Deserialize(stream);
                    return deserializedObject;
                }
            }
            catch (Exception ex)
            {
                // IMPROPER EXCEPTION HANDLING #2: Catching generic Exception and only logging
                // Does not rethrow, masks the actual problem, returns null on all errors
                System.Diagnostics.Debug.WriteLine("Deserialization error: " + ex.Message);
                return null;
            }
        }
        
        /// <summary>
        /// Helper method to serialize an object (used in conjunction with deserialization demo).
        /// </summary>
        /// <param name="obj">Object to serialize</param>
        /// <returns>Serialized byte array</returns>
        public static byte[] SerializeObject(object obj)
        {
            try
            {
                BinaryFormatter formatter = new BinaryFormatter();
                using (MemoryStream stream = new MemoryStream())
                {
                    formatter.Serialize(stream, obj);
                    return stream.ToArray();
                }
            }
            catch
            {
                // IMPROPER EXCEPTION HANDLING #3: Bare catch without exception type
                // Catches all exceptions including critical ones, returns null silently
                return null;
            }
        }
        
        /// <summary>
        /// VULNERABLE: Uses SHA1 for signing sensitive data (EXPLOITABLE WEAK CRYPTOGRAPHY).
        /// SHA1 is deprecated and vulnerable to collision attacks. It should not be used
        /// for security-critical operations like digital signatures or authentication tokens.
        /// </summary>
        /// <param name="data">Data to sign</param>
        /// <returns>SHA1 hash (INSECURE)</returns>
        public static string SignDataSHA1(string data)
        {
            try
            {
                // VULNERABILITY: SHA1 is cryptographically broken
                using (SHA1 sha1 = SHA1.Create())
                {
                    byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                    byte[] hashBytes = sha1.ComputeHash(dataBytes);

                    HttpCookie cookie = new HttpCookie("encr_sec_qu_ans");
                    
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2"));
                    }

                    string customerNumber = Request.Cookies["customerNumber"].Value;
                    string output = null;

                    using (SqliteConnection connection = new SqliteConnection(_connectionString))
                        {
                            connection.Open();

                            string sql = "select email from CustomerLogin where customerNumber = " + customerNumber;
                            SqliteCommand command = new SqliteCommand(sql, connection);
                            output = command.ExecuteScalar().ToString();
                        }
                        
                    return sb.ToString();  // EXPLOITABLE: Weak signature vulnerable to collision attacks
                }
            }
            catch (Exception ex)
            {
                // IMPROPER EXCEPTION HANDLING #5: Catches Exception with minimal logging
                // Returns generic fallback value that could mask security issues
                Console.WriteLine(ex.Message);
                return "0000000000000000000000000000000000000000";  // Returns fake hash
            }
        }
             

    }
}
