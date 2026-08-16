1. OAuth2 autoloading fails on Linux
    The namespace is DAO\OAuth2, but its directory is named DAO/Oauth2. Composer PSR-4 paths are case-sensitive on Linux. I confirmed that autoloading this interface returns false.
    [UserInformation.php (line 3)](Z:/home/aherne/framework/security/src/DAO/Oauth2/UserInformation.php:3)
    Rename the directory to OAuth2 or consistently rename the namespace to Oauth2.
2. Encrypted tokens have no integrity protection
    [Encryption.php (line 31)](Z:/home/aherne/framework/security/src/Token/Encryption.php:31) uses AES-CBC without an authentication tag or HMAC. Modified ciphertext is decrypted without first proving authenticity. The result is subsequently passed to unrestricted unserialize() in:
    [SynchronizerToken persistence (line 91)](Z:/home/aherne/framework/security/src/PersistenceDrivers/SynchronizerToken/PersistenceDriver.php:91)
    [Remember-me persistence (line 62)](Z:/home/aherne/framework/security/src/PersistenceDrivers/RememberMe/PersistenceDriver.php:62)
    Use AES-256-GCM, or encrypt-then-MAC with the MAC verified before decryption. Prefer an explicit JSON representation of LoggedInUserInfo; otherwise restrict allowed_classes and verify the resulting type.
3. XML authorization has an XPath-injection sink
    [RolesDetector.php (line 53)](Z:/home/aherne/framework/security/src/Configuration/RolesDetector.php:53) inserts the request URI directly into an XPath expression:
    "...[@id='".$matchingValue."']"
    A URI containing XPath syntax can potentially select another route policy. Iterate through <route> nodes and compare their id attributes using strict PHP equality instead of constructing XPath dynamically.
4. OAuth2 lacks state validation
    [Oauth2.php (line 78)](Z:/home/aherne/framework/security/src/Security/Authentication/Oauth2.php:78) redirects to the provider and later exchanges code, but never creates or validates OAuth state. The current [Oauth2Service (line 12)](Z:/home/aherne/framework/security/src/Oauth2Service.php:12) contract does not provide a way to validate it either.
    That permits login-CSRF/account-session swapping. Generate a cryptographically random state, persist it for the pending authorization request, and validate it before exchanging the code.
    Medium priority
5. Explicit bearer tokens do not take precedence
    [UserInfo.php (line 34)](Z:/home/aherne/framework/security/src/Detectors/UserInfo.php:34) loads persistence drivers in XML order. Because session is configured first, a valid session can cause an explicitly supplied bearer token to be ignored entirely.
    If accessToken !== "", locate the synchronizer-token driver and load only that credential. An invalid or expired explicit bearer token should not silently fall back to session or remember-me identity.
6. OAuth side effects occur before MFA completes
    [Oauth2.php (line 85)](Z:/home/aherne/framework/security/src/Security/Authentication/Oauth2.php:85) calls the DAO before entering PENDING_MFA. The DAO contract explicitly says it may save the provider access token. If MFA expires, [Wrapper MFA (line 75)](Z:/home/aherne/framework/security/src/Wrapper/MultiFactorAuthentication.php:75) clears persistence but cannot roll back that DAO operation.
    Elegantly separating these operations would help:
    Resolve OAuth identity before MFA.
    Commit/store the external access token only after final MFA success.
    Alternatively, keep it in a server-side pending transaction and commit or discard that transaction.
7. Logout is vulnerable to forced-logout CSRF
    Both logout implementations execute based solely on URI:
    [Form logout (line 56)](Z:/home/aherne/framework/security/src/Security/Authentication/Form.php:56)
    [OAuth logout (line 44)](Z:/home/aherne/framework/security/src/Security/Authentication/Oauth2.php:44)
    Require POST plus a CSRF token. Similarly, [TOTP setup/challenge (line 89)](Z:/home/aherne/framework/security/src/Security/MultiFactorAuthentication/Totp.php:89) should only consume submitted codes on POST, preventing codes from entering URLs, history, and logs.
8. Guest CSRF currently works through accidental type coercion
    The login token is generated for user ID 0, but [SynchronizerToken::decode() (line 73)](Z:/home/aherne/framework/security/src/Token/SynchronizerToken.php:73) converts 0 to null through empty(). It is then accepted because [CsrfToken (line 61)](Z:/home/aherne/framework/security/src/Detectors/CsrfToken.php:61) uses loose comparison, so null == 0.
    Preserve zero in decode() and compare strictly, or use an explicit string subject such as "guest".
9. User ID 0 is inconsistently supported
    Form authentication accepts ID 0 because it checks !== null, but authorization treats it as a guest:
    [ByXML authorization (line 53)](Z:/home/aherne/framework/security/src/Security/Authorization/ByXML/Authorization.php:53)
    [ByDAO authorization (line 41)](Z:/home/aherne/framework/security/src/Security/Authorization/ByDao/Authorization.php:41)
    Either declare zero invalid everywhere or replace truthiness checks with !== null.
10. Configuring both authorization mechanisms silently disables the second
    [Security\\Authorization (line 35)](Z:/home/aherne/framework/security/src/Security/Authorization.php:35) stops after its first result. ByDAO always produces a result, so by_route is unreachable whenever both are configured.
    Either make them mutually exclusive during configuration validation or define explicit combination semantics.
11. Multi-driver persistence writes are not atomic
    Login and MFA promotion save drivers sequentially:
    [Authentication wrapper (line 96)](Z:/home/aherne/framework/security/src/Wrapper/Authentication.php:96)
    [MFA wrapper (line 95)](Z:/home/aherne/framework/security/src/Wrapper/MultiFactorAuthentication.php:95)
    If a later driver throws, earlier drivers retain the new state. A central saveAll() coordinator could track successful writes and clear/roll them back on failure.
12. Optional access token is an uninitialized typed property
    [Request.php (line 14)](Z:/home/aherne/framework/security/src/Request.php:14) declares $accessToken without a default, but Wrapper always calls getAccessToken(). A request without setAccessToken() therefore throws.
    It should default to "".


Lower-priority hardening
    Validate decrypted JSON structure and the deserialized object type before using it.
    Protect session metadata access against absent $_SESSION["ip"] and $_SESSION["time"].
    Prevent TOTP replay by recording the last successfully consumed counter; throttling does not prevent reuse of the same valid code.
    Consider secure cookie defaults: authenticated cookies currently default to HttpOnly=false and Secure=false.
    Validate token secrets for adequate entropy and validate all expiration values as positive integers.