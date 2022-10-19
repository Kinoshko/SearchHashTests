namespace SearchHashTests.Models
{
    public  class DynamicAnalisysResults
    {
        /// <summary>
        /// The number of detected objects with Malware (red) or Adware and other (yellow) statuses.
        /// </summary>
        public List<Detection> Detections { get; set; }

        /// <summary>
        /// The number of suspicious activities with High (red), Medium (yellow), or Low (grey) levels.
        /// </summary>
        public List<SuspiciousActivity> SuspiciousActivities { get; set; }

        /// <summary>
        /// The number of files that were downloaded or dropped by the file during the execution process,
        /// and the proportion of files with the status of Malicious (extracted files that can be classified as malicious, in red),
        /// Adware and other (extracted files that can be classified as Not-a-virus, in yellow),
        /// Clean (extracted files that can be classified as not malicious, in green),
        /// or Not categorized (no information about the extracted files is available, in grey).
        /// </summary>
        public List<ExtractedFile> ExtractedFiles { get; set; }

        /// <summary>
        /// The number of registered network interactions that the file performed during the execution process
        /// and the proportion of network interactions with the status of Dangerous (requests to resources with the Dangerous status, in red),
        /// Adware and other (requests to resources with the Adware and other status, in yellow),
        /// Good (requests to resources with the Good status, in green),
        /// or Not categorized (requests to resources with the Not categorized status, in grey).
        /// </summary>
        public List<NetworkActivity> NetworkActivities { get; set; }

        /// <summary>
        /// Detects related to the analyzed file.
        /// </summary>
        public List<DynamicDetection> DynamicDetections { get; set; }

        /// <summary>
        /// SNORT and Suricata rules triggered during analysis of traffic from the file.
        /// </summary>
        public List<TriggeredNetworkRule> TriggeredNetworkRules { get; set; }


        public class Detection
        {
            /// <summary>
            /// Color of the zone of the detected object (Red or Yellow).
            /// </summary>
            public Zone Zone { get; set; }

            /// <summary>
            /// Number of objects that belong to the zone.
            /// </summary>
            public int Count { get; set; }
        }

        public class SuspiciousActivity
        {
            /// <summary>
            /// Color of the zone of the activity (Red, Yellow, or Grey).
            /// </summary>
            public Zone Zone { get; set; }

            /// <summary>
            /// Number of activities that belong to the zone.
            /// </summary>
            public int Count { get; set; }
        }

        public class ExtractedFile
        {
            /// <summary>
            /// Color of the zone of the file (Red, Yellow, Green, or Grey).
            /// </summary>
            public Zone Zone { get; set; }

            /// <summary>
            /// Number of files that belong to the zone.
            /// </summary>
            public int Count { get; set; }
        }

        public class NetworkActivity
        {
            /// <summary>
            /// Color of the zone of the network activity (Red, Yellow, Green, or Grey).
            /// </summary>
            public Zone Zone { get; set; }

            /// <summary>
            /// Number of network activities that belong to the zone.
            /// </summary>
            public int Count { get; set; }
        }

        public class DynamicDetection
        {
            /// <summary>
            /// Color of the zone of the detected object (Red or Yellow).
            /// </summary>
            public Zone Zone { get; set; }

            /// <summary>
            /// Number of detected objects that belong to the zone
            /// </summary>
            public int Threat { get; set; }
        }

        public class TriggeredNetworkRule
        {
            /// <summary>
            /// Color of the zone of the triggered rule (Red or Yellow).
            /// </summary>
            public Zone Zone { get; set; }

            /// <summary>
            /// Name of the triggered rule.
            /// </summary>
            public string RuleName { get; set; }
        }
    }
}
