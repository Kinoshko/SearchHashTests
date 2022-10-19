using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace SearchHashTests.Models
{
    public class HashResponseObject
    {
        /// <summary>
        /// Color of the zone that a hash belongs to. Available values:
        /// Red—The file can be classified as Malware.
        /// Yellow—The file is classified as Adware and other(Adware, Pornware, and other programs).
        /// Green—The file has the Clean or No threats detected status.
        /// The No threats detected status is applied if the file was not classified by Kaspersky,
        /// but it was previously scanned and/or analyzed, and no threats were detected at the time of the analysis.
        /// Grey—No data or not enough information is available for the hash.
        /// </summary>
        public Zone Zone { get; set; }

        /// <summary>
        /// General information about the requested hash.
        /// </summary>
        public FileGeneralInfo FileGeneralInfo { get; set; }

        /// <summary>
        /// Information about detected objects.
        /// </summary>
        public List<DetectionInfo> DetectionsInfo { get; set; }

        /// <summary>
        /// Information about dynamic analysis results.
        /// </summary>
        public DynamicAnalisysResults DynamicAnalisysResults { get; set; }

        public static HashResponseObject FromJson(string jsonString)
        {
            JsonSerializer serializer = new JsonSerializer()
            {
                ContractResolver = new CamelCasePropertyNamesContractResolver()
            };
            if (string.IsNullOrEmpty(jsonString))
            {
                return null;
            }

            using var jsonTextReader = new JsonTextReader(new StringReader(jsonString));
            return serializer.Deserialize<HashResponseObject>(jsonTextReader);
        }
    }
}
