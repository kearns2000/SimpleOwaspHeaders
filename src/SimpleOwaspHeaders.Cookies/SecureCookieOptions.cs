using Microsoft.AspNetCore.Http;

namespace SimpleOwaspHeaders.Cookies;

public sealed class SecureCookieOptions
{
    public bool HttpOnly { get; set; } = true;

    public bool Secure { get; set; } = true;

    public SameSiteMode SameSite { get; set; } = SameSiteMode.Strict;
}
