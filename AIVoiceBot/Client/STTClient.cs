using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace AIVoiceBot.Client
{
    public class STTClient
    {
        private readonly HttpClient _httpClient;
        private readonly string _apiKey; // Or use OAuth2 Bearer token

        public STTClient(string apiKey)
        {
            _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
            _httpClient = new HttpClient();
        }

        public async Task<string> RecognizeAsync(byte[] audioBytes, int sampleRate, string languageCode = "tr-TR")
        {
            if (audioBytes == null || audioBytes.Length == 0)
                throw new ArgumentException("Audio bytes cannot be null or empty.", nameof(audioBytes));

            string contentStr = Convert.ToBase64String(audioBytes);
            var requestUri = $"https://speech.googleapis.com/v1/speech:recognize?alt=json&key={_apiKey}";

            var requestBody = new
            {
                config = new
                {
                    encoding = "LINEAR16", // Change if your audio format is different
                    sampleRateHertz = sampleRate, // Change to match your audio
                    languageCode = languageCode
                },
                audio = new
                {
                    content = contentStr
                }
            };

            var json = JsonSerializer.Serialize(requestBody);
            using var content = new StringContent(json, Encoding.UTF8, "application/json");

            using var response = await _httpClient.PostAsync(requestUri, content);
            response.EnsureSuccessStatusCode();

            var responseString = await response.Content.ReadAsStringAsync();
            using var doc = JsonDocument.Parse(responseString);

            // Parse the first alternative transcript
            if (doc.RootElement.TryGetProperty("results", out var results) && results.GetArrayLength() > 0)
            {
                var alternatives = results[0].GetProperty("alternatives");
                if (alternatives.GetArrayLength() > 0)
                {
                    return alternatives[0].GetProperty("transcript").GetString();
                }
            }
            else
            {
                throw new InvalidOperationException("No speech recognized in the audio.");
            }

            return string.Empty;
        }
    }
}
