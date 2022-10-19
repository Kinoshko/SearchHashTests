using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SearchHashTests.Models
{
    public class DetectionInfo
    {
        /// <summary>
        /// Date and time when the object was last detected by Kaspersky expert systems.
        /// </summary>
        public string LastDetectDate { get; set; }

        /// <summary>
        /// Link to the detected object's description in the Kaspersky threats website (if available).
        /// </summary>
        public string DescriptionUrl { get; set; }

        /// <summary>
        /// Color of the zone that the detected object belongs to.
        /// </summary>
        public Zone Zone { get; set; }

        /// <summary>
        /// Name of the detected object.
        /// </summary>
        public string DetectionName { get; set; }

        /// <summary>
        /// Method used to detect the object.
        /// </summary>
        public string DetectionMethod { get; set; }

    }
}
