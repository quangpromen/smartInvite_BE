namespace SmartInvite.Api.Common;

public sealed record ErrorDetails(
    string Code,
    string Message,
    IReadOnlyDictionary<string, string[]> Fields,
    string TraceId);

public sealed record ErrorEnvelope(ErrorDetails Error);

