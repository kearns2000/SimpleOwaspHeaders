using System;
using System.Collections.Immutable;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace SimpleOwaspHeaders.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SimpleOwaspHeadersAnalyzer : DiagnosticAnalyzer
{
    private const string OptionsExtensionsType = "SimpleOwaspHeaders.SimpleOwaspHeadersOptionsExtensions";
    private const string BuilderType = "SimpleOwaspHeaders.Policies.SecurityHeaderPolicyBuilder";
    private const string SecureHeadersAttributeType = "SimpleOwaspHeaders.Metadata.SecureHeadersAttribute";
    private const string AddServicesMethod = "AddSimpleOwaspHeaders";
    private const string UseMiddlewareMethod = "UseSimpleOwaspHeaders";

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics { get; } =
        ImmutableArray.Create(
            DiagnosticDescriptors.PathPrefixMustStartWithSlash,
            DiagnosticDescriptors.InvalidRegexPattern,
            DiagnosticDescriptors.EmptyNamedPolicy,
            DiagnosticDescriptors.MissingUseMiddleware,
            DiagnosticDescriptors.CoepRequiresCorp);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeAttribute, SyntaxKind.Attribute);
        context.RegisterCompilationStartAction(AnalyzeCompilation);
    }

    private static void AnalyzeCompilation(CompilationStartAnalysisContext context)
    {
        var tracker = new RegistrationTracker();

        context.RegisterSyntaxNodeAction(
            syntaxContext =>
            {
                if (syntaxContext.Node is not InvocationExpressionSyntax invocation)
                {
                    return;
                }

                var symbol = syntaxContext.SemanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
                if (symbol is null)
                {
                    return;
                }

                if (symbol.Name == AddServicesMethod &&
                    symbol.ContainingType?.ToDisplayString() ==
                    "SimpleOwaspHeaders.SimpleOwaspHeadersServiceCollectionExtensions")
                {
                    Interlocked.Exchange(ref tracker.HasAddServices, 1);
                }

                if (symbol.Name == UseMiddlewareMethod &&
                    symbol.ContainingType?.ToDisplayString() ==
                    "SimpleOwaspHeaders.SimpleOwaspHeadersApplicationBuilderExtensions")
                {
                    Interlocked.Exchange(ref tracker.HasUseMiddleware, 1);
                }
            },
            SyntaxKind.InvocationExpression);

        context.RegisterCompilationEndAction(endContext =>
        {
            if (IsLibraryAssembly(endContext.Compilation.AssemblyName))
            {
                return;
            }

            if (tracker.HasAddServices == 1 && tracker.HasUseMiddleware == 0)
            {
                endContext.ReportDiagnostic(Diagnostic.Create(
                    DiagnosticDescriptors.MissingUseMiddleware,
                    Location.None));
            }
        });
    }

    private static void AnalyzeAttribute(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not AttributeSyntax attributeSyntax)
        {
            return;
        }

        var symbol = context.SemanticModel.GetSymbolInfo(attributeSyntax).Symbol;
        if (symbol is not IMethodSymbol attributeConstructor)
        {
            return;
        }

        if (attributeConstructor.ContainingType.ToDisplayString() != SecureHeadersAttributeType)
        {
            return;
        }

        if (attributeSyntax.ArgumentList?.Arguments.FirstOrDefault()?.Expression is not LiteralExpressionSyntax literal ||
            literal.Token.Value is not string policyName)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(policyName))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.EmptyNamedPolicy,
                literal.GetLocation()));
        }
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not InvocationExpressionSyntax invocation)
        {
            return;
        }

        var method = context.SemanticModel.GetSymbolInfo(invocation).Symbol as IMethodSymbol;
        if (method is null)
        {
            return;
        }

        var containingType = method.ContainingType?.ToDisplayString();
        var methodName = method.Name;

        if (containingType == OptionsExtensionsType)
        {
            AnalyzePathExtension(context, invocation, methodName);
            return;
        }

        if (containingType == BuilderType)
        {
            AnalyzeBuilderChain(context, invocation, methodName);
        }
    }

    private static void AnalyzePathExtension(
        SyntaxNodeAnalysisContext context,
        InvocationExpressionSyntax invocation,
        string methodName)
    {
        if (methodName == "ForPathRegex")
        {
            ValidateRegexPattern(context, invocation);
            return;
        }

        if (methodName != "ForPath")
        {
            return;
        }

        var arguments = invocation.ArgumentList?.Arguments;
        if (arguments is null || arguments.Value.Count == 0)
        {
            return;
        }

        if (arguments.Value.Count >= 2 &&
            arguments.Value[1].Expression is LiteralExpressionSyntax namedLiteral &&
            namedLiteral.Token.Value is string namedPolicy &&
            string.IsNullOrWhiteSpace(namedPolicy))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.EmptyNamedPolicy,
                namedLiteral.GetLocation()));
        }

        if (arguments.Value[0].Expression is LiteralExpressionSyntax prefixLiteral &&
            prefixLiteral.Token.Value is string prefix &&
            !string.IsNullOrEmpty(prefix) &&
            !prefix.StartsWith("/", StringComparison.Ordinal))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.PathPrefixMustStartWithSlash,
                prefixLiteral.GetLocation(),
                prefix));
        }
    }

    private static void ValidateRegexPattern(SyntaxNodeAnalysisContext context, InvocationExpressionSyntax invocation)
    {
        if (invocation.ArgumentList?.Arguments.FirstOrDefault()?.Expression is not LiteralExpressionSyntax literal ||
            literal.Token.Value is not string pattern)
        {
            return;
        }

        try
        {
            _ = new Regex(pattern);
        }
        catch (Exception ex)
        {
            context.ReportDiagnostic(Diagnostic.Create(
                DiagnosticDescriptors.InvalidRegexPattern,
                literal.GetLocation(),
                pattern,
                ex.Message));
        }
    }

    private static void AnalyzeBuilderChain(
        SyntaxNodeAnalysisContext context,
        InvocationExpressionSyntax invocation,
        string methodName)
    {
        if (methodName != "WithCrossOriginEmbedderPolicy")
        {
            return;
        }

        var coepArg = invocation.ArgumentList?.Arguments.FirstOrDefault()?.Expression;
        if (coepArg is null)
        {
            return;
        }

        var coepValue = coepArg switch
        {
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.Text,
            _ => context.SemanticModel.GetConstantValue(coepArg).Value?.ToString()
        };

        if (!string.Equals(coepValue, "RequireCorp", StringComparison.Ordinal))
        {
            return;
        }

        if (BuilderChainIncludesCorp(invocation))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            DiagnosticDescriptors.CoepRequiresCorp,
            coepArg.GetLocation()));
    }

    private static bool BuilderChainIncludesCorp(InvocationExpressionSyntax coepInvocation)
    {
        ExpressionSyntax? current = coepInvocation;
        while (current is InvocationExpressionSyntax invocation)
        {
            if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                memberAccess.Name.Identifier.Text == "WithCrossOriginResourcePolicy")
            {
                return true;
            }

            current = invocation.Expression switch
            {
                MemberAccessExpressionSyntax member => member.Expression,
                InvocationExpressionSyntax nested => nested,
                _ => null
            };
        }

        return false;
    }

    private static bool IsLibraryAssembly(string? assemblyName) =>
        assemblyName is "SimpleOwaspHeaders" or "SimpleOwaspHeaders.Analyzers";

    private sealed class RegistrationTracker
    {
        public int HasAddServices;
        public int HasUseMiddleware;
    }
}
