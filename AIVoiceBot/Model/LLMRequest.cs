using System.Collections.Generic;
using System.Text.Json.Serialization;

public class LLMRequest
{
    [JsonPropertyName("contents")]
    public List<Content> Contents { get; set; }

    [JsonPropertyName("systemInstruction")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Content SystemInstruction { get; set; }

    [JsonPropertyName("cachedContent")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? CachedContent { get; set; }  // Opsiyonel alan

}

public class Content
{
    [JsonPropertyName("parts")]
    public List<Part> Parts { get; set; }
}

public class Part
{
    [JsonPropertyName("text")]
    public string Text { get; set; }
}
