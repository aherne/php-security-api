The audit found 9 concrete bugs. Three are release blockers. I made no source changes and ignored the obsolete tests as requested.
Release blockers
Important functional bugs

8. Security-sensitive XML values are silently coerced
    Several parsers cast instead of validating:
    - [AbstractPersistence.php (line 17)](/Users/luciangabrielpopescu/framework/security/src/Configuration/Persistence/AbstractPersistence.php:17)
    - RememberMe and SynchronizerToken expirations
    - CSRF expiration
    - [TOTP options (line 85)](/Users/luciangabrielpopescu/framework/security/src/Configuration/MultiFactorAuthentication/Totp.php:85)
    - [Session cookie booleans (line 57)](/Users/luciangabrielpopescu/framework/security/src/Configuration/Persistence/Session.php:57)
    Confirmed examples:
    expiration="abc"       -> 0
    csrf expiration="-1"   -> -1
    regeneration="-4"      -> -4
    is_http_only="true"    -> false
    period="1.5"           -> 1
    digits="6oops"         -> 6
    window="abc"           -> 0
    An invalid same_site value is accepted by configuration and later throws a raw ValueError in the wrapper.
    Use strict shared validators: positive/nonnegative integer validation, boolean validation with invalid-value detection, and CookieSameSiteOptions::tryFrom() during configuration.

Lower severity

9. Token JSON is not validated
    [SynchronizerToken.php (line 38)](/Users/luciangabrielpopescu/framework/security/src/Token/SynchronizerToken.php:38) does not handle json_encode() failure. Its decoder assumes json_decode() returned the expected array and immediately accesses keys.
    GCM prevents external token tampering, so this is mainly a corrupted/internal-data bug, but valid API input such as an invalid-UTF-8 string ID can trigger it. Use JSON_THROW_ON_ERROR and verify the decoded structure and field types.
    Also, [UserInfo.php (line 14)](/Users/luciangabrielpopescu/framework/security/src/Detectors/UserInfo.php:14) leaves $userInfo uninitialized when directly constructed with no drivers. Initializing it to null fixes that public API edge case.
    FIXED

All src files pass PHP syntax lint. The recent coordinator rollback, OAuth state separation, authorization mutual exclusion, logout CSRF handling, authenticated payload checks in remember-me/bearer drivers, and TOTP counter consumption otherwise look coherent.
I did not classify automatic account creation before MFA, stateless-token revocation, secret-strength policy, or cookie-default policy as bugs because changing those would introduce new behavior rather than repair the current contracts.


7:22 AM

Keep the previous design:
enum SecurityEventType: string
{
    case FORM_PARAMETERS_INVALID = "form_parameters_invalid";
    case FORM_CSRF_REJECTED = "form_csrf_rejected";
    case FORM_CREDENTIALS_REJECTED = "form_credentials_rejected";
    case FORM_LOGIN_SUCCEEDED = "form_login_succeeded";

    case OAUTH_STATE_REJECTED = "oauth_state_rejected";
    case OAUTH_PROVIDER_REJECTED = "oauth_provider_rejected";
    case OAUTH_CODE_REJECTED = "oauth_code_rejected";
    case OAUTH_LOGIN_SUCCEEDED = "oauth_login_succeeded";

    case MFA_CODE_REJECTED = "mfa_code_rejected";
    case MFA_REPLAY_REJECTED = "mfa_replay_rejected";
    case MFA_SUCCEEDED = "mfa_succeeded";
    case MFA_THROTTLED = "mfa_throttled";

    case LOGOUT_CSRF_REJECTED = "logout_csrf_rejected";
    case LOGOUT_SUCCEEDED = "logout_succeeded";

    case AUTHORIZATION_REJECTED = "authorization_rejected";
}
Then:
final class SecurityEvent
{
    public function __construct(
        private SecurityEventType $type,
        private int|string|null $userID = null,
        private array $context = []
    ) {
    }

    // getters
}
And the output boundary:
interface SecurityAuditLogger
{
    public function record(SecurityEvent $event): void;
}
Every decision branch emits a typed event before returning its deliberately generic packet:
$this->auditLogger->record(
    new SecurityEvent(
        SecurityEventType::FORM_CSRF_REJECTED,
        context: ["uri" => $this->request->getUri()]
    )
);

return $this->loginFailed($configuration);
A temporary JsonFileAuditLogger, PSR-3 adapter, database logger, or SIEM adapter implements that interface. The authentication code never changes again.
So the correct architecture is:
Decision branch
    ├── typed SecurityEvent → internal audit logger
    └── generic Packet      → external caller
That preserves both observability and security: operators know the exact cause, while clients see only LOGIN_FAILED.