# Basic I/O and Wrapper integration

[Back to the README](../README.md)

![The host application supplies normalized input to the web security state machine and handles its output.](diagrams_new/io.svg)

`Wrapper` is the public state-machine entry point. Construction restores persisted identity and evaluates authentication, optional MFA, and authorization. `getOutcome()` converts the resulting internal state into `Packets\Packet|null`.

## Inputs

| Input | Required | Responsibility |
| --- | --- | --- |
| Complete `SimpleXMLElement` document | Yes | Contains the `<security>` configuration element. |
| `Request` | Yes | Carries the normalized route, context path, client IP, HTTP method, parameters, and optional bearer token. |
| `array<string,OAuth2Service>` | With OAuth2 | Maps every configured `<driver name="...">` to its provider adapter. |
| `OAuth2State` | With OAuth2 | Saves and atomically consumes provider-bound, expiring OAuth2 state. |
| `Configuration\RolesDetector` | With `authorization/by_route` | Supplies the route-to-role index parsed from application route XML. |

Classes selected through XML—credential DAOs, logout DAOs, authorization DAOs, MFA storage, and throttlers—are not constructor arguments. The configuration layer validates their class names, and deeper code constructs them without arguments.

## Build the normalized request

```php
<?php

use Lucinda\WebSecurity\Request;

$request = new Request();
$request->setUri($applicationRoute);
$request->setContextPath($applicationContextPath);
$request->setIpAddress($clientIpAddress);
$request->setMethod($httpMethod);
$request->setParameters($requestParameters);
$request->setAccessToken($bearerToken ?? "");
```

The values have precise meanings:

- `uri` is application-relative and must use the same normalization as configured routes.
- `contextPath` is prepended to local callback routes.
- `ipAddress` participates in session binding, encrypted-token validation, and throttling. Resolve proxy headers only through an application-defined trusted-proxy policy.
- `method` should normally be uppercase.
- `parameters` must include the inputs used by the matched workflow, including OAuth2 query parameters on a callback request.
- `accessToken` is the raw library authentication token with the `Bearer` prefix removed. It is not an OAuth2 provider token.

`Request` intentionally does not inspect PHP superglobals or framework request objects.

## Construct Wrapper

The smallest integration needs only XML and the request:

```php
<?php

use Lucinda\WebSecurity\Wrapper;

$xml = simplexml_load_file(__DIR__."/security.xml");
if (!$xml instanceof SimpleXMLElement) {
    throw new RuntimeException("Unable to load security configuration");
}

$wrapper = new Wrapper($xml, $request);
$outcome = $wrapper->getOutcome();
```

Call `getOutcome()` once and retain the result. It does not rerun the state machine, but it rebuilds the public representation and may generate a CSRF token.

## Supply OAuth2 integrations

Each XML driver name must match an injected array key:

```xml
<oauth2
    dao="App\Security\OAuth2LoginDAO"
    provisioning="existing_only"
    state_expiration="600"
    target_success="home"
    target_failure="login"
>
    <driver name="github" login="oauth/github" />
</oauth2>
```

```php
<?php

$wrapper = new Wrapper(
    xml: $xml,
    request: $request,
    oauth2Drivers: [
        "github" => $githubOAuth2Service,
    ],
    oauth2State: $oauth2State
);
```

`OAuth2Service` builds the provider authorization URL, exchanges the authorization code, and returns normalized provider user information. `OAuth2State` must atomically accept a valid state only once and reject expired, unknown, or provider-mismatched values.

## Supply route-role authorization

`by_route` authorization requires a role map in addition to the security XML:

```xml
<routes>
    <route id="forum" roles="GUEST, MEMBER, MODERATOR" />
    <route id="admin" roles="ADMIN" />
</routes>
```

```php
<?php

use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Wrapper;

$rolesDetector = new RolesDetector(
    xml: $routesXml,
    parentTag: "routes",
    childTag: "route",
    requiredAttribute: "id"
);

$wrapper = new Wrapper(
    xml: $securityXml,
    request: $request,
    rolesDetector: $rolesDetector
);
```

Guests are valid authorization subjects. Give them roles through the configured `DAO\UserRoles` implementation when public route-role access is required.

## Handle the outcome

```php
<?php

use Lucinda\WebSecurity\Packets\GuestUser;
use Lucinda\WebSecurity\Packets\LoggedInUser;
use Lucinda\WebSecurity\Packets\MultiFactor;
use Lucinda\WebSecurity\Packets\Security;
use Lucinda\WebSecurity\Packets\Throttling;

$outcome = $wrapper->getOutcome();

if ($outcome === null) {
    // Authorization allowed this request to continue as a guest.
    $application->dispatchGuestRequest();
    return;
}

$accessToken = $outcome->getAccessToken();
if ($accessToken !== null) {
    // Deliver the library bearer token through the application's response protocol.
    $response->setAuthenticationToken($accessToken);
}

if ($outcome instanceof GuestUser) {
    $response->renderLoginForm($outcome->getCsrfToken());
} elseif ($outcome instanceof LoggedInUser) {
    $response->dispatchAuthenticatedRequest(
        $outcome->getUserID(),
        $outcome->getCsrfToken(),
        $outcome->getCallback()
    );
} elseif ($outcome instanceof Throttling) {
    $response->handleThrottling($outcome->getStatus(), $outcome->getCallback());
} elseif ($outcome instanceof MultiFactor) {
    $response->handleMfa($outcome);
} elseif ($outcome instanceof Security) {
    $response->handleSecurityDecision(
        $outcome->getStatus(),
        $outcome->getFailureReason(),
        $outcome->getCallback()
    );
} else {
    throw new LogicException("Unsupported security packet");
}
```

The response methods above belong to the host application. The library does not define HTTP status mappings, redirect automatically, render templates, or store a bearer token on the client.

A callback is a destination for the application to interpret. Most local callbacks are prefixed with `Request::getContextPath()`; an OAuth2 initiation callback can instead be an absolute provider URL.

Do not treat every packet as a failure, and do not let an unhandled packet fall through into protected application logic. Consult the [packet reference](packets.md) for the exact status contract.
