    !!! The core problem is that AES-256-CBC only encrypts; it does not prove the ciphertext has not been modified. An attacker controlling a cookie or bearer token can alter encrypted bytes, and your code may decrypt the altered value before noticing anything is wrong.

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