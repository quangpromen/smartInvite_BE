namespace SmartInvite.Domain.Common;

public static class ErrorCodes
{
    public const string NullValue = "ERROR_NULL_VALUE";
    public const string ValidationError = "VALIDATION_ERROR";
    public const string InvalidCredentials = "INVALID_CREDENTIALS";
    public const string AuthenticationRequired = "AUTHENTICATION_REQUIRED";
    public const string InvalidRefreshToken = "INVALID_REFRESH_TOKEN";
    public const string RefreshTokenReused = "REFRESH_TOKEN_REUSED";
    public const string TokenConfigurationInvalid = "TOKEN_CONFIGURATION_INVALID";
    public const string Forbidden = "FORBIDDEN";
    public const string CsrfValidationFailed = "CSRF_VALIDATION_FAILED";
    public const string RateLimitExceeded = "RATE_LIMIT_EXCEEDED";
    public const string EmailAlreadyExists = "EMAIL_ALREADY_EXISTS";
    public const string HostNotFound = "HOST_NOT_FOUND";
    public const string InvalidHostOperation = "INVALID_HOST_OPERATION";
    public const string ConcurrencyConflict = "CONCURRENCY_CONFLICT";
    public const string InternalError = "INTERNAL_ERROR";
}
