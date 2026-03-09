using System;
using System.IO;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Collections.Generic;
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
using System.Linq;
using System.Data;
using OWASP.WebGoat.NET.App_Code.DB;
using OWASP.WebGoat.NET.App_Code;

namespace OWASP.WebGoat.NET.WebGoatCoins
{
    public partial class MyProducts : System.Web.UI.Page
    {

        private IDbProvider du = Settings.CurrentDbProvider;
        private readonly string _connectionString;
        
        protected void Page_Load(object sender, EventArgs e)
        {
            lblMessage.Visible = false;
            txtEmail.Enabled = true;
            if (!Page.IsPostBack)
                LoadComments();

            //TODO: broken 
            if (!Page.IsPostBack) 
            {
                
                DataSet ds = du.GetCatalogData();
                ddlItems.DataSource = ds.Tables[0];
                ddlItems.DataTextField = "productName";
                ddlItems.DataValueField = "productCode";
                ddlItems.DataBind();
            }
        }

        protected void btnSave_Click(object sender, EventArgs e)
        {
            try
            {
                string error_message = du.AddComment(hiddenFieldProductID.Value, txtEmail.Text, txtComment.Text);
                txtComment.Text = error_message;
                lblMessage.Visible = true;
                LoadComments();
            }
            catch(Exception ex)
            {
                lblMessage.Text = ex.Message;
                lblMessage.Visible = true;
            }
        }

        void LoadComments()
        {
            //Fill in the email address of authenticated users
            if (Request.Cookies["customerNumber"] != null)
            {
                string customerNumber = Request.Cookies["customerNumber"].Value;

                string email = null;

                using (SqliteConnection connection = new SqliteConnection(_connectionString))
                {
                    connection.Open();

                    string sql = "select email from CustomerLogin where customerNumber = " + customerNumber;
                    SqliteCommand command = new SqliteCommand(sql, connection);
                    email = command.ExecuteScalar().ToString();
                }

                txtEmail.Text = email;
                txtEmail.ReadOnly = true;
            }
        }

        protected void ddlItems_SelectedIndexChanged(object sender, EventArgs e)
        {
            Response.Redirect("ProductDetails.aspx?productNumber=" + ddlItems.SelectedItem.Value);
        }

        protected void Button1_Click(object sender, EventArgs e)
        {
            Response.Redirect("ProductDetails.aspx?productNumber=" + ddlItems.SelectedItem.Value);
        }

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

        // ========== HARD-CODED CREDENTIALS - NOT EXPLOITABLE ==========
        public static class PasswordComplexityExamples
        {
            // SAST will flag these as hard-coded passwords
            // But they are NOT actual credentials - just UI examples
            
            /// <summary>
            /// Example of a WEAK password shown to users (NOT A REAL CREDENTIAL)
            /// </summary>
            public const string ExampleWeakPassword = "password123";
            public const string ExampleStrongPassword = "Str0ngP@ssw0rd!";
            
            /// <summary>
            /// Generates password strength indicator HTML with example passwords.
            /// These hard-coded strings are display-only and NOT used for authentication.
            /// </summary>
            /// <returns>HTML showing password examples</returns>
            public static string GetPasswordStrengthExamples()
            {
                // SAST may flag this due to "password" strings
                // But this is NOT exploitable - it's just UI guidance
                HttpCookie cookie = new HttpCookie("encr_sec_qu_ans");

                return "<div class='password-examples'>" +
                       "<p>Weak: " + ExampleWeakPassword + "</p>" +
                       "<p>Strong: " + ExampleStrongPassword + "</p>" +
                       "</div>";
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

                    
                    
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hashBytes)
                    {
                        sb.Append(b.ToString("x2"));
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



/*







    public partial class ProductDetails : System.Web.UI.Page
    {
        private IDbProvider du = Settings.CurrentDbProvider;
        string customerNumber = Request.Cookies["customerNumber"].Value;
        string output = null;

        using (SqliteConnection connection = new SqliteConnection(_connectionString))
        {
            connection.Open();

            string sql = "select email from CustomerLogin where customerNumber = " + customerNumber;
            SqliteCommand command = new SqliteCommand(sql, connection);
            output = command.ExecuteScalar().ToString();
        }
    }

}
*/