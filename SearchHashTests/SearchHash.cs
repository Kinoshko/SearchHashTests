using NUnit.Framework;
using SearchHashTests.Models;
using System.Net;

namespace SearchHashTests
{
    [Parallelizable]
    public class SearchHash
    {
        private static readonly string token = Environment.GetEnvironmentVariable("Token");
        private static readonly string uri = "https://opentip.kaspersky.com/api/v1/search/hash";
        private static HttpClient client = new HttpClient()
        {
            BaseAddress = new Uri(uri)
        };

        public async Task<HashResponseObject> GetHashRequest(string hash)
        {
            using var response = await client.GetAsync($"?request={hash}");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));

            var jsonResponse = await response.Content.ReadAsStringAsync();
            var hashResponse = HashResponseObject.FromJson(jsonResponse);
            Assert.IsNotNull(hashResponse);
            return hashResponse;
        }

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            client.DefaultRequestHeaders.Add("x-api-key", token);
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            client?.Dispose();
        }

        [TestCase("e10713a4a5f635767dcd54d609bed977")]
        public async Task SearchHash_Malware_ZoneRed(string hash)
        {
            var hashResponse = await GetHashRequest(hash);

            Assert.That(hashResponse.Zone, Is.EqualTo(Zone.Red));
            Assert.That(hashResponse.FileGeneralInfo.FileStatus, Is.EqualTo("Malware"));
        }

        [TestCase("71ae19843de2d5563e96a3a031b05d132b2a3109")]
        public async Task SearchHash_Clean_ZoneGreen(string hash)
        {
            var hashResponse = await GetHashRequest(hash);

            Assert.That(hashResponse.Zone, Is.EqualTo(Zone.Green));
            Assert.That(hashResponse.FileGeneralInfo.FileStatus, Is.EqualTo("Clean"));
        }

        [TestCase("4cfdc2e157eefe6facb983b1d557b3a1")]
        public async Task SearchHash_NotCategorized_ZoneGrey(string hash)
        {
            var hashResponse = await GetHashRequest(hash);

            Assert.That(hashResponse.Zone, Is.EqualTo(Zone.Grey));
            Assert.That(hashResponse.FileGeneralInfo.FileStatus, Is.EqualTo("NotCategorized"));
        }

        // Файл есть в базе, но нет информации о hash типа Sha1 (4cfdc2e157eefe6facb983b1d557b3a1)
        // похоже на баг, кажется, должен быть ответ 204
        [TestCase("5116c28e651a19013822c09e5c70c9fc425a66dc")]
        public async Task SearchHash_Unknown_BadRequest(string hash)
        {
            using var response = await client.GetAsync($"?request={hash}");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }
    }
}
