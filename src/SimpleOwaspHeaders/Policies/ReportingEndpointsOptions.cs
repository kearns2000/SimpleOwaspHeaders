namespace SimpleOwaspHeaders.Policies;

public sealed class ReportingEndpointsOptions
{
    public IReadOnlyDictionary<string, string> Endpoints { get; init; }
        = new Dictionary<string, string>();

    public string BuildValue()
    {
        if (Endpoints.Count == 0)
        {
            return string.Empty;
        }

        return string.Join(", ", Endpoints.Select(e => $"{e.Key}=\"{e.Value}\""));
    }
}
