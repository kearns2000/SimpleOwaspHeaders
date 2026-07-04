using System.Net;
using System.Text;

namespace SimpleOwaspHeaders.Diagnostics;

internal static class SecurityHeadersHtmlRenderer
{
    private const string SharedStyles = """
        :root { color-scheme: light dark; font-family: system-ui, sans-serif; line-height: 1.5; }
        body { margin: 0; padding: 1.5rem; background: #f6f8fa; color: #1f2328; }
        .wrap { max-width: 1200px; margin: 0 auto; }
        .banner { background: #fff8c5; border: 1px solid #d4a72c; border-radius: 8px; padding: 1rem; margin-bottom: 1.5rem; }
        .card { background: #fff; border: 1px solid #d0d7de; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem; }
        h1, h2, h3 { margin-top: 0; }
        form { display: flex; gap: 0.5rem; flex-wrap: wrap; align-items: center; margin-bottom: 1rem; }
        input[type=text] { flex: 1 1 16rem; padding: 0.5rem 0.75rem; border: 1px solid #d0d7de; border-radius: 6px; }
        button, .chip, .nav-link { display: inline-block; padding: 0.45rem 0.75rem; border-radius: 6px; text-decoration: none; font-size: 0.925rem; }
        button { background: #0969da; color: #fff; border: 0; cursor: pointer; }
        .chip, .nav-link { background: #eef2f7; color: #1f2328; border: 1px solid #d0d7de; margin: 0.25rem 0.35rem 0.25rem 0; }
        .chip:hover, .nav-link:hover { background: #dbe8f7; }
        .nav { margin-bottom: 1rem; }
        table { width: 100%; border-collapse: collapse; font-size: 0.925rem; }
        th, td { border-bottom: 1px solid #d0d7de; padding: 0.75rem; vertical-align: top; text-align: left; }
        th { background: #f6f8fa; }
        .matrix-wrap { overflow-x: auto; }
        .matrix td, .matrix th { white-space: nowrap; max-width: 18rem; overflow: hidden; text-overflow: ellipsis; }
        .matrix td.changed { background: #fff1a8; }
        .matrix tr.diff-row td:first-child { font-weight: 600; }
        code, .mono { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; word-break: break-all; }
        .muted { color: #656d76; }
        .chain { list-style: none; padding: 0; margin: 0; }
        .chain li { padding: 0.5rem 0; border-bottom: 1px solid #eef2f7; }
        .chain li:last-child { border-bottom: 0; }
        .scenario-grid { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr)); }
        .scenario-card { border: 1px solid #d0d7de; border-radius: 8px; padding: 1rem; background: #fafbfc; }
        .scenario-card.ignored { opacity: 0.85; }
        .tag { display: inline-block; padding: 0.15rem 0.45rem; border-radius: 999px; font-size: 0.75rem; background: #ddf4ff; color: #0969da; margin-left: 0.35rem; }
        @media (prefers-color-scheme: dark) {
          body { background: #0d1117; color: #e6edf3; }
          .card, th { background: #161b22; }
          .card, th, td, input[type=text], .chip, .nav-link, .scenario-card { border-color: #30363d; }
          .banner { background: #3d2e00; border-color: #9e6a03; color: #e6edf3; }
          .chip, .nav-link { background: #21262d; color: #e6edf3; }
          .chip:hover, .nav-link:hover { background: #30363d; }
          .muted { color: #8b949e; }
          .chain li { border-color: #21262d; }
          .scenario-card { background: #0d1117; }
          .matrix td.changed { background: #3d2e00; }
          .tag { background: #13253b; color: #79c0ff; }
        }
        """;

    public static string Render(SecurityHeadersReport report)
    {
        var sb = new StringBuilder();
        WriteDocumentStart(sb, "SimpleOwaspHeaders Report");
        WriteNavigation(sb, active: "report");

        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <h1>SimpleOwaspHeaders Report</h1>");
        sb.AppendLine($"      <p class=\"muted\">Default preset: <code>{Encode(report.DefaultPreset)}</code></p>");

        sb.AppendLine("      <form method=\"get\" action=\"/_simple-owasp-headers/report\">");
        sb.AppendLine("        <label for=\"path\">Preview path</label>");
        sb.AppendLine($"        <input id=\"path\" name=\"path\" type=\"text\" value=\"{Encode(report.RequestPath)}\" />");
        sb.AppendLine("        <button type=\"submit\">Preview</button>");
        sb.AppendLine("      </form>");

        if (report.PathPreviews.Count > 0)
        {
            sb.AppendLine("      <p class=\"muted\">Configured routes:</p>");
            sb.AppendLine("      <div>");
            foreach (var link in report.PathPreviews)
            {
                sb.AppendLine(
                    $"        <a class=\"chip\" href=\"/_simple-owasp-headers/report?path={EncodeUri(link.Path)}\">{Encode(link.Label)}</a>");
            }
            sb.AppendLine("      </div>");
        }

        sb.AppendLine("    </div>");

        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine($"      <h2>Policy resolution for <code>{Encode(report.RequestPath)}</code></h2>");

        if (report.Resolution.IsIgnored)
        {
            sb.AppendLine("      <p>This path is listed in <code>IgnoredPaths</code>. The middleware does not apply security headers here.</p>");
        }
        else
        {
            sb.AppendLine("      <ol class=\"chain\">");
            foreach (var step in report.Resolution.Steps)
            {
                var role = step.Role == PolicyResolutionRole.Base ? "Base" : "Override";
                sb.AppendLine($"        <li><strong>{Encode(role)}:</strong> {Encode(step.Source)}</li>");
            }
            sb.AppendLine("      </ol>");
            sb.AppendLine("      <p class=\"muted\">Endpoint <code>[SecureHeaders]</code> policies apply when visiting the actual route and are not simulated by path preview.</p>");
        }

        sb.AppendLine("    </div>");

        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <h2>Applied headers</h2>");

        if (report.Headers.Count == 0)
        {
            sb.AppendLine("      <p>No security headers apply to this path.</p>");
        }
        else
        {
            WriteHeaderTable(sb, report.Headers);
        }

        sb.AppendLine("    </div>");
        WriteDocumentEnd(sb);
        return sb.ToString();
    }

    public static string RenderMatrix(SecurityHeadersConfigurationMatrix matrix)
    {
        var sb = new StringBuilder();
        WriteDocumentStart(sb, "SimpleOwaspHeaders Configuration Matrix");
        WriteNavigation(sb, active: "matrix");

        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <h1>Configuration matrix</h1>");
        sb.AppendLine($"      <p class=\"muted\">Default preset: <code>{Encode(matrix.DefaultPreset)}</code>. Compare effective headers across all configured routes.</p>");
        sb.AppendLine("    </div>");

        if (matrix.HeaderComparisons.Count > 0)
        {
            sb.AppendLine("    <div class=\"card\">");
            sb.AppendLine("      <h2>Header comparison</h2>");
            sb.AppendLine("      <p class=\"muted\">Highlighted cells differ from the default policy at <code>/</code>.</p>");
            sb.AppendLine("      <div class=\"matrix-wrap\">");
            sb.AppendLine("        <table class=\"matrix\">");
            sb.AppendLine("          <thead><tr><th>Header</th>");

            foreach (var cell in matrix.HeaderComparisons[0].Cells)
            {
                sb.AppendLine($"            <th>{Encode(cell.ScenarioLabel)}</th>");
            }

            sb.AppendLine("          </tr></thead>");
            sb.AppendLine("          <tbody>");

            foreach (var row in matrix.HeaderComparisons)
            {
                var rowClass = row.DiffersFromDefault ? " class=\"diff-row\"" : string.Empty;
                sb.AppendLine($"            <tr{rowClass}>");
                sb.AppendLine($"              <td><code>{Encode(row.HeaderName)}</code></td>");

                foreach (var cell in row.Cells)
                {
                    var cssClass = cell.DiffersFromDefault ? " class=\"changed mono\"" : " class=\"mono\"";
                    var value = string.IsNullOrEmpty(cell.Value) ? "—" : cell.Value;
                    sb.AppendLine($"              <td{cssClass}>{Encode(value)}</td>");
                }

                sb.AppendLine("            </tr>");
            }

            sb.AppendLine("          </tbody>");
            sb.AppendLine("        </table>");
            sb.AppendLine("      </div>");
            sb.AppendLine("    </div>");
        }

        if (matrix.NamedPolicies.Count > 0)
        {
            sb.AppendLine("    <div class=\"card\">");
            sb.AppendLine("      <h2>Named policies</h2>");
            sb.AppendLine("      <p class=\"muted\">Effective headers when each named policy is merged onto the default policy.</p>");

            foreach (var named in matrix.NamedPolicies)
            {
                sb.AppendLine("      <h3>" + Encode(named.Name) + "</h3>");
                sb.AppendLine("      <p class=\"muted\">Referenced by: " + Encode(string.Join(", ", named.ReferencedBy)) + "</p>");
                sb.AppendLine("      <table>");
                sb.AppendLine("        <thead><tr><th>Header</th><th>Value</th></tr></thead>");
                sb.AppendLine("        <tbody>");

                foreach (var (name, value) in named.MergedHeaders.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase))
                {
                    sb.AppendLine("          <tr>");
                    sb.AppendLine($"            <td><code>{Encode(name)}</code></td>");
                    sb.AppendLine($"            <td class=\"mono\">{Encode(value)}</td>");
                    sb.AppendLine("          </tr>");
                }

                sb.AppendLine("        </tbody>");
                sb.AppendLine("      </table>");
            }

            sb.AppendLine("    </div>");
        }

        sb.AppendLine("    <div class=\"card\">");
        sb.AppendLine("      <h2>Configured scenarios</h2>");
        sb.AppendLine("      <div class=\"scenario-grid\">");

        foreach (var scenario in matrix.Scenarios)
        {
            var cssClass = scenario.IsIgnored ? "scenario-card ignored" : "scenario-card";
            sb.AppendLine($"        <div class=\"{cssClass}\">");
            sb.AppendLine($"          <h3>{Encode(scenario.Label)}</h3>");
            sb.AppendLine($"          <p class=\"muted\">Sample path: <code>{Encode(scenario.SamplePath)}</code>");

            if (scenario.IsIgnored)
            {
                sb.AppendLine("            <span class=\"tag\">Ignored</span>");
            }

            sb.AppendLine("          </p>");

            if (!scenario.IsIgnored && scenario.ResolutionSteps.Count > 0)
            {
                sb.AppendLine("          <ol class=\"chain\">");
                foreach (var step in scenario.ResolutionSteps)
                {
                    sb.AppendLine($"            <li>{Encode(step)}</li>");
                }

                sb.AppendLine("          </ol>");
            }

            if (scenario.IsIgnored)
            {
                sb.AppendLine("          <p>No headers applied.</p>");
            }
            else
            {
                sb.AppendLine($"          <p class=\"muted\">{scenario.Headers.Count} header(s)</p>");
                sb.AppendLine($"          <p><a class=\"chip\" href=\"/_simple-owasp-headers/report?path={EncodeUri(scenario.SamplePath)}\">Open path report</a></p>");
            }

            sb.AppendLine("        </div>");
        }

        sb.AppendLine("      </div>");
        sb.AppendLine("    </div>");

        WriteDocumentEnd(sb);
        return sb.ToString();
    }

    private static void WriteHeaderTable(StringBuilder sb, IReadOnlyList<AppliedHeaderInfo> headers)
    {
        sb.AppendLine("      <table>");
        sb.AppendLine("        <thead><tr><th>Header</th><th>Value</th><th>What it secures</th></tr></thead>");
        sb.AppendLine("        <tbody>");

        foreach (var header in headers)
        {
            sb.AppendLine("          <tr>");
            sb.AppendLine($"            <td><code>{Encode(header.Name)}</code><br /><span class=\"muted\">{Encode(header.SecurityInfo.Summary)}</span></td>");
            sb.AppendLine($"            <td class=\"mono\">{Encode(header.Value)}</td>");
            sb.AppendLine($"            <td>{Encode(header.SecurityInfo.ThreatsMitigated)}</td>");
            sb.AppendLine("          </tr>");

            if (header.CspDirectives is { Count: > 0 })
            {
                sb.AppendLine("          <tr>");
                sb.AppendLine("            <td colspan=\"3\">");
                sb.AppendLine("              <table>");
                sb.AppendLine("                <thead><tr><th>CSP directive</th><th>Value</th><th>Summary</th></tr></thead>");
                sb.AppendLine("                <tbody>");

                foreach (var directive in header.CspDirectives)
                {
                    sb.AppendLine("                  <tr>");
                    sb.AppendLine($"                    <td><code>{Encode(directive.Directive)}</code></td>");
                    sb.AppendLine($"                    <td class=\"mono\">{Encode(directive.Value)}</td>");
                    sb.AppendLine($"                    <td>{Encode(directive.Summary)}</td>");
                    sb.AppendLine("                  </tr>");
                }

                sb.AppendLine("                </tbody>");
                sb.AppendLine("              </table>");
                sb.AppendLine("            </td>");
                sb.AppendLine("          </tr>");
            }
        }

        sb.AppendLine("        </tbody>");
        sb.AppendLine("      </table>");
    }

    private static void WriteDocumentStart(StringBuilder sb, string title)
    {
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"en\">");
        sb.AppendLine("<head>");
        sb.AppendLine("  <meta charset=\"utf-8\" />");
        sb.AppendLine("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
        sb.AppendLine($"  <title>{Encode(title)}</title>");
        sb.AppendLine("  <style>");
        sb.AppendLine(SharedStyles);
        sb.AppendLine("  </style>");
        sb.AppendLine("</head>");
        sb.AppendLine("<body>");
        sb.AppendLine("  <div class=\"wrap\">");
        sb.AppendLine("    <div class=\"banner\"><strong>Development diagnostics only.</strong> Disable <code>EnableDiagnosticsEndpoint</code> in production — this page exposes your security configuration.</div>");
    }

    private static void WriteNavigation(StringBuilder sb, string active)
    {
        sb.AppendLine("    <div class=\"nav\">");
        sb.AppendLine(active == "report"
            ? "      <span class=\"chip\">Path report</span>"
            : "      <a class=\"nav-link\" href=\"/_simple-owasp-headers/report\">Path report</a>");
        sb.AppendLine(active == "matrix"
            ? "      <span class=\"chip\">Configuration matrix</span>"
            : "      <a class=\"nav-link\" href=\"/_simple-owasp-headers/matrix\">Configuration matrix</a>");
        sb.AppendLine("      <a class=\"nav-link\" href=\"/_simple-owasp-headers\">JSON diagnostics</a>");
        sb.AppendLine("    </div>");
    }

    private static void WriteDocumentEnd(StringBuilder sb)
    {
        sb.AppendLine("  </div>");
        sb.AppendLine("</body>");
        sb.AppendLine("</html>");
    }

    private static string Encode(string? value) => WebUtility.HtmlEncode(value ?? string.Empty);

    private static string EncodeUri(string value) => WebUtility.UrlEncode(value) ?? string.Empty;
}
