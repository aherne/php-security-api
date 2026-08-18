    !!! The core problem is that AES-256-CBC only encrypts; it does not prove the ciphertext has not been modified. An attacker controlling a cookie or bearer token can alter encrypted bytes, and your code may decrypt the altered value before noticing anything is wrong.

6. OAuth side effects occur before MFA completes
    [Oauth2.php (line 85)](Z:/home/aherne/framework/security/src/Security/Authentication/Oauth2.php:85) calls the DAO before entering PENDING_MFA. The DAO contract explicitly says it may save the provider access token. If MFA expires, [Wrapper MFA (line 75)](Z:/home/aherne/framework/security/src/Wrapper/MultiFactorAuthentication.php:75) clears persistence but cannot roll back that DAO operation.
    Elegantly separating these operations would help:
    Resolve OAuth identity before MFA.
    Commit/store the external access token only after final MFA success.
    Alternatively, keep it in a server-side pending transaction and commit or discard that transaction.



Lower-priority hardening
    Validate decrypted JSON structure and the deserialized object type before using it.
    Protect session metadata access against absent $_SESSION["ip"] and $_SESSION["time"].
    Prevent TOTP replay by recording the last successfully consumed counter; throttling does not prevent reuse of the same valid code.
    Consider secure cookie defaults: authenticated cookies currently default to HttpOnly=false and Secure=false.
    Validate token secrets for adequate entropy and validate all expiration values as positive integers.