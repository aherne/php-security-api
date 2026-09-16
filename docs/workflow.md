# Internal request workflow

[Documentation map](index.md) · [Outcomes](outcomes.md) · [Authentication lifecycle](multi-factor-authentication.md#authentication-lifecycle)

This is a request-processing model. Persisted authentication state has its own, smaller lifecycle; do not confuse a packet outcome with a new stored state.

![Restore identity, run authentication/MFA/authorization conditionally, and build the public outcome.](diagrams/request-flow.svg)

## Numbered paths

1. **Prepare and restore:** `Wrapper` parses configuration, creates configured persistence/CSRF helpers, and restores the first available identity.
2. **Authentication:** evaluate configured form/OAuth2/login/logout behavior. Synchronize any accepted persistence transition with held identity.
3. **MFA:** run only if authentication returned `null`. Evaluate pending deadlines, authenticated freshness, user policy, and TOTP processing; synchronize completion or expiry.
4. **Authorization:** run only if MFA returned `null`. Pass an authenticated user ID or `null` for a guest.
5. **Stage packet:** any non-null stage result stops the remaining security stages. This includes transition/success packets as well as failures.
6. **Public representation:** `getOutcome()` preserves actionable packets or represents completed identity as `LoggedInUser`, preserving an applicable callback and adding CSRF data. It attaches an available bearer token to a non-null packet.

If all stages return `null`, the public builder returns `LoggedInUser` for held authenticated identity, or `null` for a guest without another packet.

## Construction versus getter

`new Wrapper(...)` executes security processing. `getOutcome()` does not rerun authentication/MFA/authorization, but it does build the public packet again and may generate an authenticated-user CSRF token.

Call the getter once, retain the result, and deliver any token replacement before committing the response.

## Responsibility boundaries

| Layer | Responsibility |
| --- | --- |
| `Configuration\...` | Detect and validate XML settings and implementation classes. |
| `Security\...` | Evaluate authentication, MFA, and resource policies. |
| `Wrapper\...` | Bind request/state/dependencies and coordinate accepted persistence changes. |
| `Wrapper\Coordinator` | Save across selected drivers and attempt compensating/all-driver cleanup. |
| `Wrapper\OutcomeBuilder` | Select and enrich the caller-facing packet. |
| Application | Implement policy interfaces, normalize input, and handle responses. |

The main wrapper does not expose separate identity/token/CSRF getters. Logically related result data is carried in packets.

## Important shortcuts

- Primary identity with MFA configured becomes pending and returns `null` internally so MFA runs in the same request.
- Accepted login without MFA returns a stage packet and skips authorization on that request.
- Successful MFA/pending NOT_REQUIRED promotes identity and returns a stage packet.
- Already authenticated NOT_REQUIRED returns `null` from the MFA wrapper so authorization continues.
- Fresh authenticated MFA validity skips reevaluation; stale or absent validity reevaluates policy.
- A login-form `GuestUser` packet ends security processing for that form request.

These paths explain why a simple straight pipeline or a diagram where every status is a persistent state would misrepresent the API.
