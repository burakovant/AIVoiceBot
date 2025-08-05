using System;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Collections.Generic;
using WebSocketSharp;
using Org.BouncyCastle.Asn1.Ocsp;

namespace AIVoiceBot.Client
{
    internal class LLMClient
    {
        private readonly string _apiKey;
        private readonly string _systemPrompt;
        private readonly HttpClient _httpClient;
        private string _cachedContent;
        private const string GeminiApiUrl = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=";

        public LLMClient(string apiKey, string systemPrompt)
        {
            _apiKey = apiKey ?? throw new ArgumentNullException(nameof(apiKey));
            _systemPrompt = systemPrompt ?? throw new ArgumentNullException(nameof(systemPrompt));
            _httpClient = new HttpClient();
        }

        public async Task<string> GetChatCompletionAsync(LLMRequest llmRequest)
        {
            Content systemInstruction = new Content();
            systemInstruction.Role = "system";
            systemInstruction.Parts = new List<Part>();
            Part part = new Part();
            part.Text = _systemPrompt;
            systemInstruction.Parts.Add(part);
            llmRequest.SystemInstruction = systemInstruction;
            if (_cachedContent != null)
            {
                llmRequest.CachedContent = _cachedContent;
            }

            var json = JsonSerializer.Serialize(llmRequest);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(GeminiApiUrl + _apiKey, content);
            response.EnsureSuccessStatusCode();
            var responseString = await response.Content.ReadAsStringAsync();

            using var doc = JsonDocument.Parse(responseString);
            var root = doc.RootElement;
            var reply = root
                .GetProperty("candidates")[0]
                .GetProperty("content")
                .GetProperty("parts")[0]
                .GetProperty("text")
                .GetString();

            _cachedContent = root.TryGetProperty("cachedContent", out var cachedContentElement)
                ? cachedContentElement.GetString()
                : null;

            return reply;
        }
    }
}
