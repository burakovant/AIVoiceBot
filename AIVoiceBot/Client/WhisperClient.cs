using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using AIVoiceBot.Client;

namespace AIVoiceBot.Client
{
    public class WhisperClient
    {
        private readonly string _apiKey;
        private readonly HttpClient _httpClient;

        public WhisperClient(string apiKey)
        {
            _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _apiKey);
        }

        /// <summary>
        /// Sends audio data to OpenAI Whisper API and returns the recognized text.
        /// </summary>
        /// <param name="audioFilePath">Path to the audio file (wav/mp3/m4a, etc.)</param>
        /// <param name="language">Optional: Language code (e.g. "en")</param>
        /// <returns>Recognized text</returns>
        public async Task<string> TranscribeAsync(string audioFilePath, string language = null)
        {
            using var form = new MultipartFormDataContent();
            using var fileStream = File.OpenRead(audioFilePath);
            var fileContent = new StreamContent(fileStream);
            fileContent.Headers.ContentType = new MediaTypeHeaderValue("audio/wav");
            form.Add(fileContent, "file", Path.GetFileName(audioFilePath));
            form.Add(new StringContent("whisper-1"), "model");
            if (!string.IsNullOrEmpty(language))
                form.Add(new StringContent(language), "language");

            var response = await _httpClient.PostAsync("https://api.openai.com/v1/audio/transcriptions", form);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync();

            // Whisper API returns: { "text": "recognized text" }
            var text = System.Text.Json.JsonDocument.Parse(json).RootElement.GetProperty("text").GetString();
            return text;
        }
    }
}
