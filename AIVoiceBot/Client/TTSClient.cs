using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AIVoiceBot.Client
{
    public class TTSClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey;

        public TTSClient(string apiKey)
        {
            _apiKey = apiKey;
            _httpClient = new HttpClient();
        }

        /// <summary>
        /// Converts text to speech using Google Cloud Text-to-Speech API.
        /// </summary>
        /// <param name="text">Text to synthesize.</param>
        /// <param name="languageCode">Language code (e.g., "en-US").</param>
        /// <param name="voiceName">Optional: Specific voice name.</param>
        /// <param name="ssmlGender">Optional: SSML voice gender.</param>
        /// <returns>Audio content as byte array (WAV format).</returns>
        public async Task<byte[]> SynthesizeSpeechAsync(string text, string languageCode, string voiceName = null, string ssmlGender = "FEMALE")
        {
            var url = $"https://texttospeech.googleapis.com/v1/text:synthesize?alt=json&key={_apiKey}";

            var requestBody = new
            {
                input = new { text },
                voice = new
                {
                    languageCode,
                    name = voiceName,
                    ssmlGender
                },
                audioConfig = new
                {
                    sampleRateHertz = 8000,
                    audioEncoding = "ALAW"
                }
            };

            var json = JsonSerializer.Serialize(requestBody, new JsonSerializerOptions { IgnoreNullValues = true });
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(url, content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseJson);
            var audioContent = doc.RootElement.TryGetProperty("audioContent", out var audioElement) ? audioElement.GetString()
                : throw new InvalidOperationException("Missing audio content");

            return Convert.FromBase64String(audioContent);
        }
    }
}
