# Lucinda Security

PHP library for request authentication, authorization, CSRF protection, and authenticated-state persistence in web applications.

The package is configuration-driven: you describe security behavior in XML, provide a normalized request through `Lucinda\WebSecurity\Request`, then run everything through `Lucinda\WebSecurity\Wrapper`.

## Installation

```bash
composer require lucinda/security
```

Requirements:

- PHP `^8.1`
- `ext-SimpleXML`
- `ext-openssl`

## What It Does

This package coordinates four concerns:

- CSRF token generation and validation
- authentication by XML users, DAO-backed form login, or OAuth2
- authorization by XML routes or DAO-backed page/user checks
- persistence of authenticated state through session, remember-me cookie, synchronizer token, or JWT

The orchestration entry point is [`src/Wrapper.php`](/Users/luciangabrielpopescu/framework/security/src/Wrapper.php). It:

1. reads `<security>` from your XML
2. builds persistence drivers
3. detects the current user ID from persisted state or bearer token
4. creates the CSRF detector
5. runs authentication
6. runs authorization

If the request cannot continue normally, the wrapper throws [`src/SecurityPacket.php`](/Users/luciangabrielpopescu/framework/security/src/SecurityPacket.php) with redirect or response metadata.

## Integration Flow

1. Build an XML config that contains `<security>` and, when needed, `<users>` and `<routes>`.
2. Populate a [`src/Request.php`](/Users/luciangabrielpopescu/framework/security/src/Request.php) with URI, context path, IP, HTTP method, request parameters, and optional bearer token.
3. Instantiate `Wrapper`.
4. Catch `SecurityPacket` for login redirects, logout redirects, authorization failures, or deferred OAuth2 redirects.
5. On successful requests, use `getUserID()`, `getCsrfToken()`, and `getAccessToken()` as needed.

Minimal runtime example:

```php
<?php

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\SecurityPacket;
use Lucinda\WebSecurity\Wrapper;

$xml = simplexml_load_file("security.xml");

$request = new Request();
$request->setUri("login");
$request->setContextPath("/app");
$request->setIpAddress($_SERVER["REMOTE_ADDR"] ?? "127.0.0.1");
$request->setMethod($_SERVER["REQUEST_METHOD"] ?? "GET");
$request->setParameters($_REQUEST);
$request->setAccessToken("");

try {
    $security = new Wrapper($xml, $request);

    $userID = $security->getUserID();
    $csrf = $security->getCsrfToken();
    $accessToken = $security->getAccessToken();
} catch (SecurityPacket $packet) {
    header("Location: ".$packet->getCallback()."?status=".$packet->getStatus());
    exit;
}
```

For stateless apps, `SecurityPacket` can also carry an access token via `getAccessToken()`.

## Configuration

The wrapper expects a root XML document that contains a `<security>` element.

### Top-Level Shape

```xml
<xml>
    <security>
        <csrf secret="change-me"/>
        <persistence>
            <session/>
            <synchronizer_token secret="change-me"/>
        </persistence>
        <authentication>
            <form
                dao="App\Security\UserAuthenticationDAO"
                throttler="App\Security\LoginThrottler">
                <login page="login" target="index"/>
                <logout page="logout" target="login"/>
            </form>
        </authentication>
        <authorization>
            <by_dao
                page_dao="App\Security\PageAuthorizationDAO"
                user_dao="App\Security\UserAuthorizationDAO"/>
        </authorization>
    </security>
</xml>
```

### `security.csrf`

Required. Used both for login-form CSRF validation and OAuth2 `state`.

Attributes:

- `secret` required
- `expiration` optional, defaults to `600` seconds

### `security.persistence`

Optional. If present, one or more drivers may be registered.

Supported drivers:

- `session`
  - `parameter_name` optional, default `uid`
  - `expiration` optional
  - `is_http_only` optional, `0` or `1`
  - `is_https_only` optional, `0` or `1`
  - `same_site` optional
  - `handler` optional custom `SessionHandlerInterface`
- `remember_me`
  - `secret` required
  - `parameter_name` optional, default `uid`
  - `expiration` optional, default `86400`
  - `is_http_only` optional, `0` or `1`
  - `is_https_only` optional, `0` or `1`
  - `same_site` optional
- `synchronizer_token`
  - `secret` required
  - `expiration` optional, default `3600`
  - `regeneration` optional, default `60`
- `json_web_token`
  - `secret` required
  - `expiration` optional, default `3600`
  - `regeneration` optional, default `60`

Token-based persistence drivers are what power `Wrapper::getAccessToken()`.

### `security.authentication`

Required. At least one method must be configured.

#### Form Authentication

Use `<form>` for username/password login.

- `dao` optional
  - if present, the class must implement [`src/Authentication/DAO/UserAuthenticationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/DAO/UserAuthenticationDAO.php)
  - if omitted, credentials are checked against the XML `<users>` section
- `throttler` required for `<form>`
  - must extend the package login throttling abstraction used by form authentication

Optional child tags:

- `<login page="login" target="index" parameter_username="username" parameter_password="password" parameter_rememberMe="remember_me" />`
- `<logout page="logout" target="login" />`

Parameter defaults:

- username: `username`
- password: `password`
- remember-me: `remember_me`

#### OAuth2 Authentication

Use `<oauth2>` when login should be delegated to one or more provider drivers.

Attributes:

- `dao` required
  - must implement [`src/Authentication/OAuth2/VendorAuthenticationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/OAuth2/VendorAuthenticationDAO.php)
- `login` optional, default `login`
- `logout` optional, default `logout`
- `target` optional, default `index`

You must also pass OAuth2 driver instances implementing [`src/Authentication/OAuth2/Driver.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/OAuth2/Driver.php) as the third constructor argument to `Wrapper`.

### `security.authorization`

Required. Choose one method.

#### `by_route`

Authorizes requests using XML route roles. This requires a `<routes>` section and, depending on authentication mode, either:

- a `<users>` section with per-user roles, or
- an authentication DAO that can also provide roles

`by_route` may define:

- `logged_in_callback` optional
- `logged_out_callback` optional

#### `by_dao`

Authorizes requests through application DAOs.

Attributes:

- `page_dao` required, must extend [`src/Authorization/DAO/PageAuthorizationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authorization/DAO/PageAuthorizationDAO.php)
- `user_dao` required, must extend [`src/Authorization/DAO/UserAuthorizationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authorization/DAO/UserAuthorizationDAO.php)
- `logged_in_callback` optional, default `index`
- `logged_out_callback` optional, default `login`

### `users`

Needed when form authentication is XML-backed and/or when route authorization resolves roles from XML.

```xml
<users roles="GUEST">
    <user id="1" username="john" password="...bcrypt hash..." roles="USER"/>
</users>
```

Notes:

- `users@roles` describes guest roles
- `user@password` should be produced with PHP `password_hash`
- if route authorization needs user roles, `user@roles` must be present

### `routes`

Needed for `by_route` authorization.

```xml
<routes roles="GUEST">
    <route id="login" roles="GUEST,USER"/>
    <route id="index" roles="USER"/>
</routes>
```

## Main Contracts

These are the key extension points you implement in application code:

- [`src/Authentication/DAO/UserAuthenticationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/DAO/UserAuthenticationDAO.php): username/password login and logout against your persistence layer
- [`src/Authentication/OAuth2/VendorAuthenticationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/OAuth2/VendorAuthenticationDAO.php): map provider identities to local users
- [`src/Authentication/OAuth2/Driver.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/OAuth2/Driver.php): vendor-specific OAuth2 operations
- [`src/Authorization/DAO/PageAuthorizationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authorization/DAO/PageAuthorizationDAO.php): resolve the requested page into your authorization model
- [`src/Authorization/DAO/UserAuthorizationDAO.php`](/Users/luciangabrielpopescu/framework/security/src/Authorization/DAO/UserAuthorizationDAO.php): decide whether the current user can access the resolved page
- [`src/Authorization/UserRoles.php`](/Users/luciangabrielpopescu/framework/security/src/Authorization/UserRoles.php): provide role lists for route-based authorization

## Outcomes And Exceptions

`Wrapper` either completes normally or throws.

### Normal Completion

- `getUserID()` returns `int|string|null`
- `getCsrfToken()` returns a fresh CSRF token for the current user context
- `getAccessToken()` returns the current token only when a token persistence driver is active

### `SecurityPacket`

[`src/SecurityPacket.php`](/Users/luciangabrielpopescu/framework/security/src/SecurityPacket.php) is the main control-flow exception. It carries:

- `getCallback()`
- `getStatus()`
- `getAccessToken()`
- `getTimePenalty()`

Observed statuses in the package tests include:

- `login_ok`
- `login_failed`
- `logout_ok`
- `logout_failed`
- `redirect`
- `unauthorized`
- `forbidden`
- `not_found`

### Other Exceptions

Depending on the configured flow, you may also see:

- [`src/ConfigurationException.php`](/Users/luciangabrielpopescu/framework/security/src/ConfigurationException.php) for invalid XML or invalid class wiring
- token exceptions from [`src/Token/Exception.php`](/Users/luciangabrielpopescu/framework/security/src/Token/Exception.php) and [`src/Token/EncryptionException.php`](/Users/luciangabrielpopescu/framework/security/src/Token/EncryptionException.php)
- OAuth2 failures from [`src/Authentication/OAuth2/Exception.php`](/Users/luciangabrielpopescu/framework/security/src/Authentication/OAuth2/Exception.php)
- session hijack detection from [`src/PersistenceDrivers/Session/HijackException.php`](/Users/luciangabrielpopescu/framework/security/src/PersistenceDrivers/Session/HijackException.php)

## Testing

The repository uses `lucinda/unit-testing`, not PHPUnit.

Run the full suite with:

```bash
php test.php
```

Representative integration coverage lives in [`tests/WrapperTest.php`](/Users/luciangabrielpopescu/framework/security/tests/WrapperTest.php), which exercises:

- DAO-backed form authentication
- XML-backed form authentication
- OAuth2 authentication
- route-based authorization
- DAO-based authorization
- token-based authenticated flows
