# Quick start

[Documentation map](index.md) · [Configuration](configuration.md) · [Outcomes](outcomes.md)

This guide uses one scenario: session persistence, form login, and DAO authorization, without OAuth2 or MFA.

## 1. Install

```bash
composer require lucinda/security
```

PHP `^8.1`, SimpleXML, and OpenSSL are required.

## 2. Prepare the configuration

Copy [examples/security.xml](examples/security.xml) to your application's `security.xml`. Replace the CSRF secret with a private, deployment-managed value. The example enables secure cookies and assumes HTTPS.

It declares `login` and `logout` as application-relative routes. All request routes and configured routes must use the same normalization.

## 3. Implement the application contracts

The example class names are placeholders. Make them autoloadable and implement these interfaces:

| Example class | Required interface | Responsibility |
| --- | --- | --- |
| `App\Security\FormLoginDAO` | `Lucinda\WebSecurity\DAO\FormLogin` | Validate credentials; return an eligible, non-empty local ID or `null`. |
| `App\Security\FormLoginThrottler` | `Lucinda\WebSecurity\DAO\Throttler\FormLogin` | Persist rejected attempts and decide whether username/IP attempts are blocked. |
| `App\Security\LogoutDAO` | `Lucinda\WebSecurity\DAO\Logout` | Perform application-side logout operations; return acceptance or rejection. |
| `App\Security\PageAuthorizationDAO` | `Lucinda\WebSecurity\DAO\PageAuthorization` | Resolve page IDs and identify public pages. |
| `App\Security\UserAuthorizationDAO` | `Lucinda\WebSecurity\DAO\UserAuthorization` | Check an authenticated user's permission for a page and HTTP method. |

The library constructs these classes without constructor arguments. Arrange any application infrastructure they require accordingly. Configuration validates the contracts but does not instantiate these objects.

Use your real password-verification and durable throttling logic; do not substitute an always-successful DAO or a no-op throttler in production.

## 4. Normalize each request

Construct [Request](../src/Request.php) from your router or HTTP framework:

```php
use Lucinda\WebSecurity\Request;

// Values below are supplied by your application's request adapter.
$request = new Request();
$request->setUri($route);
$request->setContextPath($contextPath);
$request->setIpAddress($clientIp);
$request->setMethod($method);
$request->setParameters($parameters);
```

Set all four required scalar fields before constructing `Wrapper`. Supply an uppercase HTTP method and an application-relative route. Parameters default to an empty array; the bearer token defaults to an empty string.

For this session example, no bearer token or additional constructor dependency is needed. Resolve client IPs using your trusted-proxy rules.

## 5. Execute and handle the outcome

```php
use Lucinda\WebSecurity\Wrapper;

$xml = simplexml_load_file(__DIR__ . "/security.xml");
if ($xml === false) {
    throw new RuntimeException("Unable to load security.xml.");
}

$wrapper = new Wrapper($xml, $request);
$outcome = $wrapper->getOutcome();
```

Construction executes the workflow. `getOutcome()` builds the public representation; it does not repeat authentication. Prefer calling it once per request.

Connect [outcome handling](outcomes.md) to your response layer. Render a login form for `GuestUser`, use `LoggedInUser` as completed identity data, handle other decisions explicitly, and continue as a guest when the outcome is `null`.

## Try the complete request sequence

1. Request `GET login`: render the `GuestUser` packet's CSRF token as a hidden field named `csrf`.
2. Submit `POST login` with `username`, `password`, and that token.
3. On accepted credentials, handle the `LoggedInUser` success callback. Session persistence is updated.
4. Request `home`: page authorization runs. Make this page public or grant the user's permission.
5. Submit `POST logout` with the authenticated-user CSRF token; accepted logout clears persistence.

Login/MFA completion packets can stop later stages on that request. Protect the destination request through the normal workflow rather than treating a success callback as an authorization grant.

## Add capabilities progressively

- Add [MFA](multi-factor-authentication.md) by configuring its DAO, throttler, routes, and TOTP method.
- Add [OAuth2](authentication.md#oauth2) by configuring provider names and supplying provider services plus an `OAuth2State` store.
- Switch to [route-role authorization](authorization.md#route-role-authorization) by supplying a `RolesDetector`.
- Choose [bearer-token persistence](persistence.md#authentication-bearer-tokens) only with an explicit token delivery and client-storage policy.
