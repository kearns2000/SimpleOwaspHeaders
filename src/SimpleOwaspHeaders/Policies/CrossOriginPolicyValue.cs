namespace SimpleOwaspHeaders.Policies;

public enum CrossOriginResourcePolicyValue
{
    SameOrigin,
    SameSite,
    CrossOrigin
}

public enum CrossOriginOpenerPolicyValue
{
    SameOrigin,
    SameOriginAllowPopups,
    UnsafeNone
}

public enum CrossOriginEmbedderPolicyValue
{
    RequireCorp,
    UnsafeNone
}
