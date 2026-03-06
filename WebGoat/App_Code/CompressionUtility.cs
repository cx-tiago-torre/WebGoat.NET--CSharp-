using System;
using System.IO;
using System.Text;
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
    }
}
