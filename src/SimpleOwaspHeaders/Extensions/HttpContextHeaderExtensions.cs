namespace SimpleOwaspHeaders.Extensions;

internal static class HttpContextHeaderExtensions
{
    public static void TryAddSecurityHeader(this HttpContext context, string name, string value)
    {
        if (context.Response.Headers.ContainsKey(name))
        {
            return;
        }

#pragma warning disable ASP0019
        context.Response.Headers.Append(name, value);
#pragma warning restore ASP0019
    }
}
