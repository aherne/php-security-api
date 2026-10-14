# Exceptions that can escape the state machine

[Back to the README](../README.md) · [Packets](packets.md)

![Exception categories used by the state machine; this page documents the green framework exceptions.](diagrams_new/exceptions.svg)

Expected security decisions are returned as packets. Exceptions indicate that the state machine could not safely produce an ordinary decision because configuration, persistence, token data, a required dependency, or an internal invariant was invalid.

This page documents only the green framework exception types in the diagram.

## `Configuration\Exception`

Full name: `Lucinda\WebSecurity\Configuration\Exception`

Thrown when configuration cannot define a valid state machine, including:

- a required `security` section, child tag, or attribute is absent;
- an integer, boolean, or enum-backed attribute is invalid;
- persistence or authorization tags are combined illegally;
- an XML-selected class does not implement its required interface;
- a route-role XML entry lacks its identifier or `roles` attribute;
- a successful MFA result violates the required validity-timestamp invariant.

Treat this as a deployment or programming error. Log the sanitized message and stop request processing; do not continue as a guest.

## `PersistenceDrivers\Exception`

Full name: `Lucinda\WebSecurity\PersistenceDrivers\Exception`

Thrown when authentication persistence cannot be trusted or completed, including:

- session startup, save, clear, or ID regeneration fails;
- stored session metadata or serialized authentication state is invalid;
- a remember-me cookie cannot be issued;
- saving through multiple persistence drivers fails and compensating cleanup is incomplete.

Persistence changes are coordinated as best-effort compensation, not as a database transaction. If a save fails, the coordinator clears every driver whose save was attempted in reverse order. When cleanup also fails, this exception reports the incomplete rollback and retains the original save failure as its previous exception.

Treat the request as failed. Do not infer that the user is either authenticated or safely logged out after an incomplete persistence operation.

## `PersistenceDrivers\Session\HijackException`

Full name: `Lucinda\WebSecurity\PersistenceDrivers\Session\HijackException`

Thrown when authentication state exists in the session but its recorded client IP differs from `Request::getIpAddress()`. The session driver attempts to clear the session before throwing it.

The mismatch is evidence of an invalid security context, not proof of malicious behavior; legitimate network changes can also alter an address. Reject the authenticated request, record only non-sensitive audit information, and require a new login. Ensure the application resolves client addresses consistently behind trusted proxies.

## `Token\EncodingException`

Full name: `Lucinda\WebSecurity\Token\EncodingException`

Thrown when no trustworthy token representation can be produced or decoded. Covered failures include:

- JSON encoding or decoding failure;
- an invalid encrypted envelope or Base64 component;
- failure to generate encryption initialization material;
- authenticated encryption or decryption failure.

For an incoming token, reject the credential and do not use any partial data. For an outgoing-token failure, fail the operation because the new authentication state cannot be delivered safely.

## `Token\ValidationException`

Full name: `Lucinda\WebSecurity\Token\ValidationException`

Thrown after token decoding succeeds but its contents are invalid for the current context, including:

- an invalid payload shape or scalar type;
- a token issued for a different client IP;
- a decoded persistence payload that cannot be restored as `LoggedInUserInfo`.

Reject the credential and require authentication again. Do not expose structural details to the client or log the token value.

`EncodingException` means trustworthy decoded data was never obtained; `ValidationException` means decoded data existed but failed semantic or security-context validation.

## `Security\Exception`

Full name: `Lucinda\WebSecurity\Security\Exception`

Thrown when the configured workflow lacks a required runtime dependency or receives invalid authentication state. Current cases include:

- OAuth2 is configured without both provider adapters and an `OAuth2State` implementation;
- the configured OAuth2 driver name has no matching injected `OAuth2Service`;
- `by_route` authorization runs without a `RolesDetector`;
- persisted authentication state is constructed with an empty local user ID.

Treat this as an integration or corrupted-state failure, not as ordinary denied access.

## `Packets\Exception`

Full name: `Lucinda\WebSecurity\Packets\Exception`

Thrown when `Packets\Throttling` receives an enum case other than authentication `LOGIN_THROTTLED` or MFA `THROTTLED`.

Normal state-machine paths use the correct cases, so this usually identifies direct packet misuse or an internal programming error. Do not translate it into a throttling response.

## Application boundary

Both operations below may throw:

```php
$wrapper = new Wrapper($xml, $request, $oauth2Drivers, $oauth2State, $rolesDetector);
$outcome = $wrapper->getOutcome();
```

Place them inside the application's normal exception boundary. A safe boundary should:

1. stop protected application processing;
2. avoid returning authenticated or guest success by default;
3. log the exception type and sanitized context without tokens, passwords, MFA codes, or enrollment secrets;
4. return an application-controlled error response;
5. alert or audit session-context and token-validation failures according to application policy.

Packets remain the only normal mechanism for login failure, logout failure, authorization denial, MFA workflow states, and throttling.
