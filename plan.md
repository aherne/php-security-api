The audit found 9 concrete bugs. Three are release blockers. I made no source changes and ignored the obsolete tests as requested.
Release blockers
1. Critical: enrolled TOTP can be replaced without the old factor
    [Totp.php (line 89)](/Users/luciangabrielpopescu/framework/security/src/Security/MultiFactorAuthentication/Totp.php:89) enters setup() before checking whether the user already has a secret at line 97.
    A user with a stolen password can:
    1. Complete primary authentication.
    2. Request the MFA setup route.
    3. Receive a newly generated secret.
    4. Validate that new secret.
    5. Cause enable() to overwrite the victim’s existing secret.
    I reproduced this with a DAO returning an existing secret; the result was still SETUP_REQUIRED, and a replacement setup secret was saved.
    Setup must be allowed only when getSecret($userID) === null. Put the enrolled-secret check before route dispatch and also guard setup() defensively.

2. High: successful form login crashes
    [RememberMeTicked.php (line 41)](/Users/luciangabrielpopescu/framework/security/src/Detectors/RememberMeTicked.php:41) calls two removed APIs:
    getMethods()
    getLoginPolicy()
    The current APIs are:
    getLoginMethods()
    getParameterRememberMe()
    Every successful form POST reaches this detector before persistence and currently throws:
    Error: Call to undefined method ...Authentication::getMethods()
    FIXED

3. High: OAuth classes will fail PSR-4 autoloading on Linux
    The macOS filesystem is hiding incomplete case-only renames. Git currently tracks:
    src/Oauth2Service.php
    src/Oauth2ApprovalStatus.php
    But the code refers to OAuth2Service and OAuth2ApprovalStatus. Additionally, [OAuth2ApprovalStatus.php (line 5)](/Users/luciangabrielpopescu/framework/security/src/OAuth2ApprovalStatus.php:5) declares Oauth2ApprovalStatus.
    Composer’s optimized autoloader explicitly reports the enum as non-PSR-4-compliant and skips it. On a case-sensitive Linux clone, OAuth2Service will also not resolve.
    Force the filename changes through temporary names with git mv, and rename the enum declaration to OAuth2ApprovalStatus.
Important functional bugs

4. User ID 0 is still unsupported
    This regression is present in several layers:
    - [LoggedInUserInfo.php (line 20)](/Users/luciangabrielpopescu/framework/security/src/PersistenceDrivers/LoggedInUserInfo.php:20) rejects 0 and "0".
    - [Form.php (line 65)](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/Form.php:65) treats ID 0 as logged out and a DAO result of 0 as login failure.
    - [Oauth2.php (line 78)](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/Oauth2.php:78) treats it as logged out.
    - [Logout.php (line 57)](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/Logout.php:57) treats it as already logged out.
    - [SynchronizerToken.php (line 73)](/Users/luciangabrielpopescu/framework/security/src/Token/SynchronizerToken.php:73) decodes it as null.
    - Both authorization implementations classify it as a guest.
    - [ByDao/Authorization.php (line 41)](/Users/luciangabrielpopescu/framework/security/src/Security/Authorization/ByDao/Authorization.php:41) also treats page ID 0 as nonexistent.
    Use explicit === null/!== null checks. For LoggedInUserInfo, reject only the empty string, not integer or string zero.

5. Session payload loading is unsafe and fragile
    [Session/PersistenceDriver.php (line 87)](/Users/luciangabrielpopescu/framework/security/src/PersistenceDrivers/Session/PersistenceDriver.php:87) assumes $_SESSION["ip"] and $_SESSION["time"] exist. Missing metadata causes undefined-key errors; I reproduced this with an otherwise valid authentication record.
    At [line 103 (line 103)](/Users/luciangabrielpopescu/framework/security/src/PersistenceDrivers/Session/PersistenceDriver.php:103), unrestricted unserialize():
    - Instantiates arbitrary serialized classes.
    - Does not verify LoggedInUserInfo.
    - Produces a return-type TypeError for corrupted records.
    I confirmed that a serialized object’s __wakeup() executes before the return-type failure. Use allowed_classes, verify instanceof LoggedInUserInfo, validate metadata, and check whether session_start() succeeds.

6. Malformed request parameters cause uncaught TypeErrors
    [Form.php (line 79)](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/Form.php:79) checks only empty(). A request such as csrf[]=x passes that test and then passes an array to CsrfToken::isValid(string ...), producing a 500-level TypeError.
    Username and password have the same problem. OAuth’s authorization code at [Oauth2.php (line 86)](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/Oauth2.php:86) is also passed to a string parameter without type validation.
    Validate all external parameters with is_string() before calling typed application/service methods.

7. OAuth provider errors restart authentication indefinitely
    At [Oauth2.php (line 86)](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/Oauth2.php:86), every response without code is treated as a new login.
    A standard callback such as:
    error=access_denied&state=...
    therefore generates another state and redirects to the provider again. I reproduced the result as DEFERRED with a new state saved.
    Handle error callbacks first: validate and consume their state, then return LOGIN_FAILED.

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