namespace SimpleOwaspHeaders.Diagnostics;

public sealed record HeaderSecurityInfo(
    string HeaderName,
    string Summary,
    string ThreatsMitigated);

internal static class HeaderSecurityGuide
{
    private static readonly Dictionary<string, HeaderSecurityInfo> Entries =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["Strict-Transport-Security"] = new(
                "Strict-Transport-Security",
                "Instructs browsers to use HTTPS only for this site.",
                "Protocol downgrade attacks, cookie hijacking over HTTP, SSL stripping."),
            ["X-Frame-Options"] = new(
                "X-Frame-Options",
                "Controls whether the page may be embedded in frames on other sites.",
                "Clickjacking — tricking users into clicking hidden UI inside an iframe."),
            ["X-Content-Type-Options"] = new(
                "X-Content-Type-Options",
                "Prevents browsers from MIME-sniffing away from the declared Content-Type.",
                "Drive-by downloads, XSS via misinterpreted file types."),
            ["Content-Security-Policy"] = new(
                "Content-Security-Policy",
                "Restricts where scripts, styles, images, and other resources may load from.",
                "Cross-site scripting (XSS), unauthorized data exfiltration, malicious embeds."),
            ["Content-Security-Policy-Report-Only"] = new(
                "Content-Security-Policy-Report-Only",
                "Evaluates a CSP without enforcing it — violations are reported only.",
                "Useful for testing CSP changes before enforcement."),
            ["X-Permitted-Cross-Domain-Policies"] = new(
                "X-Permitted-Cross-Domain-Policies",
                "Restricts Adobe Flash and PDF cross-domain policy files.",
                "Legacy cross-domain data leaks via Flash/PDF clients."),
            ["Referrer-Policy"] = new(
                "Referrer-Policy",
                "Limits how much referrer URL information is sent with requests.",
                "Sensitive URL leakage to third parties."),
            ["Cache-Control"] = new(
                "Cache-Control",
                "Directs browsers and proxies how to cache responses.",
                "Sensitive data cached on shared devices or intermediary caches."),
            ["X-XSS-Protection"] = new(
                "X-XSS-Protection",
                "Legacy IE XSS filter; modern guidance is to disable it (0).",
                "Superseded by CSP; disabling avoids inconsistent browser behaviour."),
            ["Cross-Origin-Resource-Policy"] = new(
                "Cross-Origin-Resource-Policy",
                "Declares which origins may read this resource cross-origin.",
                "Cross-origin data leaks (Spectre-class attacks, unintended embedding)."),
            ["Cross-Origin-Opener-Policy"] = new(
                "Cross-Origin-Opener-Policy",
                "Isolates the browsing context from cross-origin opener windows.",
                "Cross-window attacks such as tab-nabbing."),
            ["Cross-Origin-Embedder-Policy"] = new(
                "Cross-Origin-Embedder-Policy",
                "Requires cross-origin resources to explicitly permit embedding.",
                "Process isolation bypass via cross-origin resources without CORP."),
            ["Clear-Site-Data"] = new(
                "Clear-Site-Data",
                "Instructs the browser to clear cookies, storage, or cache for this site.",
                "Session fixation or incomplete logout on shared devices."),
            ["Reporting-Endpoints"] = new(
                "Reporting-Endpoints",
                "Defines named endpoints for browser reporting APIs.",
                "Enables monitoring of CSP and other security violations."),
            ["Permissions-Policy"] = new(
                "Permissions-Policy",
                "Controls which browser features (camera, geolocation, etc.) may be used.",
                "Unauthorized access to device capabilities via embedded content.")
        };

    public static HeaderSecurityInfo Get(string headerName) =>
        Entries.TryGetValue(headerName, out var info)
            ? info
            : new HeaderSecurityInfo(
                headerName,
                "Security response header applied by SimpleOwaspHeaders.",
                "Varies by header configuration.");
}
