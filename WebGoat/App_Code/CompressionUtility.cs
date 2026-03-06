using System;
using System.IO;
using System.Text;
using System.Web;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using ICSharpCode.SharpZipLib.GZip;
using ICSharpCode.SharpZipLib.Zip;
using ICSharpCode.SharpZipLib.Tar;
using ICSharpCode.SharpZipLib.Core;

namespace OWASP.WebGoat.NET
{
    /// <summary>
    /// Utility class for compression operations using SharpZipLib.
    /// 
    /// NOTE: This class uses SharpZipLib 0.86.0 which has CVE-2021-32840 (Path Traversal vulnerability).
    /// However, this implementation only uses NON-VULNERABLE methods:
    /// - Archive creation (ZipOutputStream, TarOutputStream, GZipOutputStream)
    /// - In-memory compression/decompression
    /// - Stream-based operations
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
            /// Example of a STRONG password shown to users (NOT A REAL CREDENTIAL)
            /// </summary>
            public const string ExampleStrongPassword = "MyP@ssw0rd!2024";
            
            /// <summary>
            /// Default placeholder text for password fields (NOT A REAL CREDENTIAL)
            /// </summary>
            public const string PasswordPlaceholder = "Enter your password";
            
            /// <summary>
            /// Example admin username for demo purposes (NOT A REAL CREDENTIAL)
            /// </summary>
            public const string ExampleAdminUser = "admin";
            
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
            
            using (MemoryStream stream = new MemoryStream(serializedData))
            {
                // EXPLOITABLE: No type validation or restrictions
                // Attacker can provide malicious serialized payload
                object deserializedObject = formatter.Deserialize(stream);
                return deserializedObject;
            }
        }
        
        /// <summary>
        /// Helper method to serialize an object (used in conjunction with deserialization demo).
        /// </summary>
        /// <param name="obj">Object to serialize</param>
        /// <returns>Serialized byte array</returns>
        public static byte[] SerializeObject(object obj)
        {
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream stream = new MemoryStream())
            {
                formatter.Serialize(stream, obj);
                return stream.ToArray();
            }
        }

        // ========== WEAK CRYPTOGRAPHY - EXPLOITABLE ==========
        
        /// <summary>
        /// VULNERABLE: Uses MD5 for password hashing (EXPLOITABLE WEAK CRYPTOGRAPHY).
        /// MD5 is cryptographically broken and should NEVER be used for password hashing.
        /// It is vulnerable to:
        /// 1. Collision attacks
        /// 2. Rainbow table attacks
        /// 3. Brute force attacks (extremely fast to compute)
        /// Passwords can be easily recovered using tools like hashcat or online rainbow tables.
        /// </summary>
        /// <param name="password">Plain text password</param>
        /// <returns>MD5 hash (INSECURE)</returns>
        public static string HashPasswordMD5(string password)
        {
            // VULNERABILITY: MD5 is broken and unsuitable for password hashing
            using (MD5 md5 = MD5.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(passwordBytes);
                
                // Convert to hex string
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                
                return sb.ToString();  // EXPLOITABLE: Weak hash easily cracked
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
            // VULNERABILITY: SHA1 is cryptographically broken
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] dataBytes = Encoding.UTF8.GetBytes(data);
                byte[] hashBytes = sha1.ComputeHash(dataBytes);
                
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashBytes)
                {
                    sb.Append(b.ToString("x2"));
                }
                
                return sb.ToString();  // EXPLOITABLE: Weak signature vulnerable to collision attacks
            }
        }

    }
}

