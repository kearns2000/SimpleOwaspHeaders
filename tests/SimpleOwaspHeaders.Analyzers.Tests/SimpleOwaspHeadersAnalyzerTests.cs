using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using SimpleOwaspHeaders.Analyzers;
using SimpleOwaspHeaders.Options;
using Xunit;

namespace SimpleOwaspHeaders.Analyzers.Tests;

public sealed class SimpleOwaspHeadersAnalyzerTests
{
  private static readonly MetadataReference LibraryReference =
      MetadataReference.CreateFromFile(typeof(SimpleOwaspHeadersOptions).Assembly.Location);

  private static readonly MetadataReference AspNetCoreReference =
      MetadataReference.CreateFromFile(typeof(Microsoft.AspNetCore.Builder.WebApplication).Assembly.Location);

  private static ImmutableArray<MetadataReference> CreateReferences(
      IEnumerable<MetadataReference> additionalReferences)
  {
    var references = new List<MetadataReference> { LibraryReference };

    var trustedAssemblies = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES"))?
        .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);

    if (trustedAssemblies is not null)
    {
      foreach (var assemblyPath in trustedAssemblies)
      {
        references.Add(MetadataReference.CreateFromFile(assemblyPath));
      }
    }

    references.AddRange(additionalReferences);
    return references.ToImmutableArray();
  }

  [Fact]
  public async Task ForPath_without_leading_slash_reports_SOH001()
  {
    const string source = """
        using SimpleOwaspHeaders;
        using SimpleOwaspHeaders.Options;
        using SimpleOwaspHeaders.Policies;

        class Program
        {
            static void Configure(SimpleOwaspHeadersOptions options)
            {
                options.ForPath("admin", policy => policy.WithContentSecurityPolicy(csp => csp.ScriptSources("'self'")));
            }
        }
        """;

    var diagnostics = await GetDiagnosticsAsync(source);
    Assert.Contains(diagnostics, d => d.Id == DiagnosticIds.PathPrefixMustStartWithSlash);
  }

  [Fact]
  public async Task ForPathRegex_with_invalid_pattern_reports_SOH002()
  {
    const string source = """
        using SimpleOwaspHeaders;
        using SimpleOwaspHeaders.Options;
        using SimpleOwaspHeaders.Policies;

        class Program
        {
            static void Configure(SimpleOwaspHeadersOptions options)
            {
                options.ForPathRegex("[", policy => policy.WithContentSecurityPolicy(csp => csp.ScriptSources("'self'")));
            }
        }
        """;

    var diagnostics = await GetDiagnosticsAsync(source);
    Assert.Contains(diagnostics, d => d.Id == DiagnosticIds.InvalidRegexPattern);
  }

  [Fact]
  public async Task SecureHeaders_with_empty_name_reports_SOH003()
  {
    const string source = """
        using SimpleOwaspHeaders.Metadata;

        [SecureHeaders("")]
        class Endpoint
        {
        }
        """;

    var diagnostics = await GetDiagnosticsAsync(source);
    Assert.Contains(diagnostics, d => d.Id == DiagnosticIds.EmptyNamedPolicy);
  }

  [Fact]
  public async Task ForPath_with_empty_named_policy_reports_SOH003()
  {
    const string source = """
        using SimpleOwaspHeaders;
        using SimpleOwaspHeaders.Options;
        using SimpleOwaspHeaders.Policies;

        class Program
        {
            static void Configure(SimpleOwaspHeadersOptions options)
            {
                options.ForPath("/admin", "");
            }
        }
        """;

    var diagnostics = await GetDiagnosticsAsync(source);
    Assert.Contains(diagnostics, d => d.Id == DiagnosticIds.EmptyNamedPolicy);
  }

  [Fact]
  public async Task Coep_require_corp_without_corp_reports_SOH005()
  {
    const string source = """
        using SimpleOwaspHeaders.Policies;

        class Program
        {
            static SecurityHeaderPolicy Build() =>
                SecurityHeaderPolicyBuilder.Create()
                    .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp)
                    .Build();
        }
        """;

    var diagnostics = await GetDiagnosticsAsync(source);
    Assert.Contains(diagnostics, d => d.Id == DiagnosticIds.CoepRequiresCorp);
  }

  [Fact]
  public async Task Coep_with_corp_in_chain_does_not_report_SOH005()
  {
    const string source = """
        using SimpleOwaspHeaders.Policies;

        class Program
        {
            static SecurityHeaderPolicy Build() =>
                SecurityHeaderPolicyBuilder.Create()
                    .WithCrossOriginResourcePolicy(CrossOriginResourcePolicyValue.SameOrigin)
                    .WithCrossOriginEmbedderPolicy(CrossOriginEmbedderPolicyValue.RequireCorp)
                    .Build();
        }
        """;

    var diagnostics = await GetDiagnosticsAsync(source);
    Assert.DoesNotContain(diagnostics, d => d.Id == DiagnosticIds.CoepRequiresCorp);
  }

  [Fact]
  public async Task Add_without_use_middleware_reports_SOH004()
  {
    const string source = """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.Extensions.DependencyInjection;
        using SimpleOwaspHeaders;

        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSimpleOwaspHeaders();
        var app = builder.Build();
        """;

    var diagnostics = await GetDiagnosticsAsync(source, OutputKind.ConsoleApplication, AspNetCoreReference);
    Assert.Contains(diagnostics, d => d.Id == DiagnosticIds.MissingUseMiddleware);
  }

  [Fact]
  public async Task Add_and_use_middleware_does_not_report_SOH004()
  {
    const string source = """
        using Microsoft.AspNetCore.Builder;
        using Microsoft.Extensions.DependencyInjection;
        using SimpleOwaspHeaders;

        var builder = WebApplication.CreateBuilder();
        builder.Services.AddSimpleOwaspHeaders();
        var app = builder.Build();
        app.UseSimpleOwaspHeaders();
        """;

    var diagnostics = await GetDiagnosticsAsync(source, OutputKind.ConsoleApplication, AspNetCoreReference);
    Assert.DoesNotContain(diagnostics, d => d.Id == DiagnosticIds.MissingUseMiddleware);
  }

  private static Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
      string source,
      params MetadataReference[] additionalReferences) =>
      GetDiagnosticsAsync(source, OutputKind.DynamicallyLinkedLibrary, additionalReferences);

  private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
      string source,
      OutputKind outputKind,
      params MetadataReference[] additionalReferences) =>
      await GetDiagnosticsAsync(source, outputKind, (IEnumerable<MetadataReference>)additionalReferences);

  private static async Task<ImmutableArray<Diagnostic>> GetDiagnosticsAsync(
      string source,
      OutputKind outputKind,
      IEnumerable<MetadataReference> additionalReferences)
  {
    var references = CreateReferences(additionalReferences);

    var compilation = CSharpCompilation.Create(
        assemblyName: "AnalyzerTests",
        syntaxTrees: [CSharpSyntaxTree.ParseText(source)],
        references: references,
        options: new CSharpCompilationOptions(outputKind));

    var compileErrors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToList();
    Assert.True(
        compileErrors.Count == 0,
        string.Join(Environment.NewLine, compileErrors.Select(d => d.ToString())));

    var analyzer = new SimpleOwaspHeadersAnalyzer();
    var compilationWithAnalyzers = compilation.WithAnalyzers(
        ImmutableArray.Create<DiagnosticAnalyzer>(analyzer));

    return await compilationWithAnalyzers.GetAnalyzerDiagnosticsAsync();
  }
}
