    !!! The core problem is that AES-256-CBC only encrypts; it does not prove the ciphertext has not been modified. An attacker controlling a cookie or bearer token can alter encrypted bytes, and your code may decrypt the altered value before noticing anything is wrong.

Lower-priority hardening
    Validate decrypted JSON structure and the deserialized object type before using it.
    Protect session metadata access against absent $_SESSION["ip"] and $_SESSION["time"].
    Prevent TOTP replay by recording the last successfully consumed counter; throttling does not prevent reuse of the same valid code.
    Consider secure cookie defaults: authenticated cookies currently default to HttpOnly=false and Secure=false.
    Validate token secrets for adequate entropy and validate all expiration values as positive integers.


Yes—this is the real remaining part of issue 6. The current contract:
login(UserInformation $userInformation, string $vendor): int|string|null
conflates three separate operations:
1. Resolve an existing account.
2. Decide whether an unknown identity may register.
3. Create that account.
null cannot distinguish “unknown,” “rejected,” or “awaiting approval.”
I would model it as follows.
Mandatory provisioning policy
Make OAuth configuration explicitly choose one:
<oauth2
    provisioning="existing_only"
    ...
/>
Supported values:
- existing_only — unknown OAuth identities are rejected.
- approval_required — record an account application and return pending.
- automatic — begin creating an account automatically.
Because there are no consumers yet, I would make the attribute mandatory rather than silently defaulting it. For approval_required, also require target_pending.
Separate lookup from provisioning
interface Oauth2Login
{
    public function resolve(
        UserInformation $userInformation,
        string $vendor
    ): int|string|null;
}
This method must be read-only.
A second optional DAO interface handles unknown identities:
interface Oauth2Provisioning
{
    public function begin(
        UserInformation $userInformation,
        string $vendor,
        ProvisioningMode $mode
    ): ProvisioningResult;

    public function finalize(string $transactionID): void;

    public function abandon(string $transactionID): void;
}
The configuration validator should require Oauth2Provisioning only for automatic and approval_required.
Resulting state machine
OAuth identity verified
        |
        +-- existing account ----------> PENDING_MFA --> AUTHENTICATED
        |
        +-- missing + existing_only ---> LOGIN_FAILED
        |
        +-- missing + approval --------> ACCOUNT_PENDING
        |                                  |
        |                            administrator approves
        |                                  |
        |                            fresh OAuth login
        |
        +-- missing + automatic ------> inactive candidate
                                           |
                                      PENDING_MFA
                                       /       \
                                  success      expiry
                                     |            |
                                  finalize      abandon
ACCOUNT_PENDING should be a new authentication result status, not an AuthenticationStage. A pending applicant is not a logged-in user, so nothing should be written to the authentication persistence drivers.
Approval should not resume the old login
The pending record should be an account application keyed by something like:
(vendor, provider_user_id)
Do not retain the OAuth access token or keep an authentication transaction alive for days:
1. Record the application.
2. Return ACCOUNT_PENDING.
3. Administrator approves or denies it externally.
4. User performs a fresh OAuth login.
5. resolve() now finds the approved account.
6. MFA proceeds normally.
The dashboard remains application code; the library only defines the provisioning contract and emits the pending outcome.
Automatic provisioning and MFA
To fully resolve the original side-effect problem, automatic should initially create an inactive candidate, not an active account. The provisioning result needs:
- A provisional local user ID, because the existing MFA API requires one.
- An opaque provisioning transaction ID.
- An expiration time.
That transaction ID must survive in the pending authentication context. On MFA success, call finalize() before marking the user authenticated. On MFA expiration, call abandon(). The DAO must also expire abandoned candidates independently because users may simply never return.
For organization-wide automatic creation, eligibility belongs in the provisioning DAO:
recognized organization/tenant → create candidate
anything else                  → rejected
It should rely on authenticated provider information, not merely an email suffix.
So the next change should be the API split and provisioning modes—not merely another condition inside the current login() method. That gives the library a coherent distinction between identity verification, account admission, account creation, MFA, and final authentication.
-------
Yes, but use one explicit mode rather than a boolean:
<oauth2
    account_creation="existing_only"
    ...
/>
Allowed values:
- existing_only
- automatic
- approval_required
Make it mandatory, since there are no consumers to preserve compatibility.
automatically_create_accounts="true|false" would cover only two states and require another attribute later for approval, potentially creating contradictory combinations.
The XML change alone is not enough, however: the current DAO login() method may perform lookup and creation internally. It must be split so the framework can enforce the configured mode:
resolve(...): int|string|null; // never creates
provision(...): ProvisioningResult; // called only when permitted
Also, automatic should mean “automatic provisioning is permitted”; the DAO may still reject identities that do not belong to the configured organization.
--------
Yes. Oauth2Service should only communicate with the provider. OAuth state is application-owned transient security data.
I would define:
interface Oauth2State
{
    public function save(
        string $state,
        string $vendor,
        int $validUntil
    ): void;

    /**
     * Atomically validates and removes the state.
     */
    public function consume(string $state, string $vendor): bool;
}
Then Security\Authentication\Oauth2 remains responsible for generating the value:
$state = bin2hex(random_bytes(32));
$this->state->save($state, $vendor, time() + 600);
And on callback:
$receivedState = $parameters["state"] ?? null;

if (
    !is_string($receivedState)
    || !$this->state->consume($receivedState, $vendor)
) {
    throw new Exception("Invalid OAuth2 state!");
}
consume() must be atomic and one-time. It should preferably store a hash of the state rather than the raw value.
Where to store it:
- Browser application: session storage is the natural implementation.
- Stateless API or multiple application servers: Redis, database, or another shared expiring store.
- Service-to-service OAuth: authorization state does not apply because there is no browser authorization-code redirect.
For a pure API supporting browser/mobile OAuth, the flow can be:
1. API generates and stores the state in Redis/database.
2. API returns the provider authorization URL.
3. Browser/mobile client follows it.
4. Provider redirects to the API callback.
5. API consumes the state directly using its value as the lookup key.
Therefore, no PHP session is required.
I would not use the existing authentication persistence drivers for this. OAuth state is pre-authentication, short-lived, multi-valued, and one-time; LoggedInUserInfo persistence has different semantics.
The wrapper should receive a single state store and pass it downward:
public function __construct(
    \SimpleXMLElement $xml,
    Request $request,
    array $oauth2Services = [],
    ?Oauth2State $oauth2State = null,
    ?\SimpleXMLElement $routes = null
)
Then validate that it is non-null only when OAuth is configured. One store can serve every provider because vendor is part of the key.
Also, store multiple simultaneous states—not one state per session—so two browser tabs can start OAuth flows without invalidating each other.
Finally, keep this state separate from account-approval state. OAuth state should expire after roughly 5–10 minutes; an account application may remain pending for days and should require a fresh OAuth login after approval.