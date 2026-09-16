# Outcomes and response handling

[Documentation map](index.md) · [Workflow](workflow.md)

`Wrapper` decides security state, not your application's response. Call `getOutcome()` and handle the returned `Packet | null`.

## Packet contract

All concrete packets inherit optional data from [Packet](../src/Packets/Packet.php):

| Getter | Meaning |
| --- | --- |
| `getUserID()` | Associated local identity, not proof that authentication completed. |
| `getCallback()` | Destination for caller-owned navigation; reading it does not redirect. |
| `getAccessToken()` | Library authentication bearer token, if available; not a provider token. |
| `getFailureReason()` | Optional detailed failure enum. |

Not every packet has a status method:

| Value / type | Additional data and behavior |
| --- | --- |
| `null` | No stage packet or authenticated identity representation is needed; continue as a guest. |
| `GuestUser` | `getCsrfToken()` for rendering the login form. |
| `LoggedInUser` | Completed identity and `getCsrfToken()`; may retain a success callback. |
| `Security` | `getStatus()`: authentication or authorization enum. |
| `MultiFactor` | MFA status; optional setup secret, provisioning URI, and validity timestamp. |
| `Throttling` | Form or MFA throttling enum status. |

Handle type before reading type-specific data. Enum backing values overlap across concerns; compare enum cases, not raw integers.

## Authentication statuses

These are `Security\Authentication\ResultStatus` cases:

| Status | Meaning |
| --- | --- |
| `IDENTITY_VERIFIED` | Internal primary-identity success; wrapper still decides MFA staging. |
| `LOGIN_OK` | Accepted login; normally converted to `LoggedInUser` in the public outcome. |
| `LOGIN_FAILED` | Rejected login; failure detail may explain why. |
| `LOGIN_PENDING` | OAuth2 account approval is pending; no completed identity. |
| `LOGOUT_OK` | Accepted logout; persistence cleanup is performed by the wrapper. |
| `LOGOUT_FAILED` | Rejected logout; held identity is not cleared by acceptance logic. |
| `DEFERRED` | Callback-based continuation, such as provider authorization or an already-satisfied login/logout request. |
| `LOGIN_THROTTLED` | Carried by `Throttling`, not the ordinary login packet. |

`LOGIN_PENDING` is unrelated to persisted `PENDING_MFA`.

## MFA statuses

These are `Security\MultiFactorAuthentication\ResultStatus` cases:

| Status | Meaning |
| --- | --- |
| `NOT_REQUIRED` | User policy does not require MFA. Pending identity is promoted; authenticated identity can continue. |
| `SETUP_REQUIRED` | Render enrollment using sensitive setup material. |
| `REQUIRED` | Render or navigate to the factor challenge. |
| `SUCCEEDED` | Verified and consumed code; successful authentication is normally represented as `LoggedInUser`. |
| `FAILED` | Code mismatch or rejected counter consumption. |
| `EXPIRED` | Pending identity's deadline is missing/reached; wrapper clears state. |
| `THROTTLED` | Carried by `Throttling`. |

Successful MFA's freshness timestamp becomes internal persisted state. Outcome building may replace the success packet with `LoggedInUser`; do not depend on a public MFA success packet being returned.

## Authorization statuses

`Security\Authorization\ResultStatus` defines `OK`, `UNAUTHORIZED`, `FORBIDDEN`, and `NOT_FOUND`. Allowed access continues without an authorization packet. Denials return a `Security` packet.

These enums are workflow decisions, not HTTP status codes. Your response layer chooses the HTTP representation.

## Handling pattern

```php
use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Packets\LoggedInUser;
use Lucinda\WebSecurity\Packets\MultiFactor;
use Lucinda\WebSecurity\Packets\Security;
use Lucinda\WebSecurity\Packets\Throttling;

$outcome = $wrapper->getOutcome();
$accessToken = $outcome?->getAccessToken();

if ($accessToken !== null) {
    // Include the replacement token in your defined response protocol.
}

if ($outcome === null) {
    // Continue as a guest.
} elseif ($outcome instanceof GuestUser) {
    // Render the login form using $outcome->getCsrfToken().
} elseif ($outcome instanceof LoggedInUser) {
    // Handle its callback or continue with completed identity data.
} elseif ($outcome instanceof Throttling) {
    // Render your blocked-attempt response or handle its callback.
} elseif ($outcome instanceof MultiFactor) {
    // Inspect the MFA enum; render setup/challenge or handle failure/expiry.
} elseif ($outcome instanceof Security) {
    // Inspect the authentication/authorization enum and handle the decision.
} else {
    throw new LogicException("Unsupported security packet.");
}
```

Comments represent your response layer; this is not a complete dispatcher. Do not allow an unhandled outcome to fall through into protected application code.

## Callbacks and delivery

Local callbacks are prefixed with the request's context path. OAuth2 initiation can return an absolute provider authorization URL.

Do not blindly redirect every packet: a challenge/setup callback may identify the page you are already rendering. Decide whether the current request should render that state or navigate elsewhere.

Outcome building preserves callbacks when converting terminal success to `LoggedInUser`. A completion callback does not imply that destination-resource authorization ran on the completion request.

Deliver bearer replacements even when the packet is a challenge or failure. On successful bearer logout, explicitly remove the client's stored token; no empty replacement token is attached.

Avoid logging CSRF/bearer tokens, passwords, submitted MFA codes, enrollment secrets, or provisioning URIs. Map detailed failure reasons to appropriately generic public messages where needed.

## Exceptions

Expected credential, permission, MFA, and throttling decisions are packets. Missing/invalid configuration, broken integrations, persistence failures, and malformed authentication tokens can throw.

Both construction and public outcome building can fail. Handle exceptions at the application boundary; do not reinterpret unexpected failures as successful guest access.

See [configuration exceptions](../src/Configuration/Exception.php), [persistence exceptions](../src/PersistenceDrivers/Exception.php), [security exceptions](../src/Security/Exception.php), and [token exceptions](../src/Token/Exception.php).
