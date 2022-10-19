using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace SearchHashTests.Models
{
    public class FileGeneralInfo
    {
        /// <summary>
        /// Status of the file requested by the hash (Malware, Adware and other, Clean, No threats detected, or Not categorized).
        /// </summary>
        public string FileStatus { get; set; }

        /// <summary>
        /// SHA-1 hash of the file requested by the hash.
        /// </summary>
        public string Sha1 { get; set; }

        /// <summary>
        /// MD5 hash of the file requested the hash.
        /// </summary>
        public string Md5 { get; set; }

        /// <summary>
        /// Date and time when the requested hash was detected by Kaspersky expert systems for the first time.
        /// </summary>
        public string FirstSeen { get; set; }

        /// <summary>
        /// Date and time when the requested hash was detected by Kaspersky expert systems for the last time.
        /// </summary>
        public string LastSeen { get; set; }

        /// <summary>
        /// Organization that signed the requested hash.
        /// </summary>
        public string Signer { get; set; }

        /// <summary>
        /// Packer name (if available).
        /// </summary>
        public string Packer { get; set; }

        /// <summary>
        /// Size of the object being investigated by the hash (in bytes).
        /// </summary>
        public int Size { get; set; }

        /// <summary>
        /// Type of the object being investigated the by hash.
        /// </summary>
        public string Type { get; set; }

        /// <summary>
        /// Number of hits (popularity) of the requested hash detected by Kaspersky expert systems.
        /// Number of hits is rounded to the nearest power of 10.
        /// </summary>
        public int HitsCount { get; set; }
    }
}
