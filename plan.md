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