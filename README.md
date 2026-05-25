# Lucinda Security

PHP library for request authentication, authorization, CSRF protection, multi-factor authentication, and authenticated-state persistence in web applications.

The package is configuration-driven: describe security behavior in XML, normalize the current request with `Lucinda\WebSecurity\Request`, then run the flow through `Lucinda\WebSecurity\Wrapper`.

## Installation

```bash
composer require lucinda/security
```

Requirements:

- PHP `^8.1`
- `ext-SimpleXML`
- `ext-openssl`

## What It Does

This package coordinates:

- CSRF token generation and validation
- form authentication through an application DAO
- OAuth2 authentication through injected service drivers
- optional TOTP multi-factor authentication
- authorization by DAO checks or XML route roles
- persistence of authenticated state through sessions, remember-me cookies, or synchronizer tokens

The orchestration entry point is [`src/Wrapper.php`](/Users/luciangabrielpopescu/framework/security/src/Wrapper.php). It reads `<security>`, creates persistence and CSRF helpers, detects the current user, runs authentication, runs optional MFA, then runs authorization.

## Quick Start

```php
<?php

use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Wrapper;
use Lucinda\WebSecurity\DAO\LoginThrottler;

$xml = simplexml_load_file("security.xml");

/** @var LoginThrottler $loginThrottler Your application implementation. */

$request = new Request();
$request->setUri("login");
$request->setContextPath("/app");
$request->setIpAddress($_SERVER["REMOTE_ADDR"] ?? "127.0.0.1");
$request->setMethod($_SERVER["REQUEST_METHOD"] ?? "GET");
$request->setParameters($_REQUEST);
$request->setAccessToken($_SERVER["HTTP_AUTHORIZATION"] ?? "");

$wrapper = new Wrapper(
    $xml,
    $request,
    [],                 // OAuth2 services, keyed by configured driver name
    $loginThrottler,    // required when form authentication is configured
    $xml                // required only for by_route authorization
);

$outcome = $wrapper->getOutcome();
if ($outcome !== null) {
    // Inspect packet status/callback and decide how your app responds.
    // Example: redirect to $outcome->getCallback().
}

$userID = $wrapper->getUserID();
$csrfToken = $wrapper->getCsrfToken();
$accessToken = $wrapper->getAccessToken();
```

`Wrapper` does not throw a control-flow packet. Use `getOutcome()` to inspect authentication, MFA, throttling, or authorization results.

## XML Configuration

The wrapper expects a root XML document containing a required `<security>` element.

Important SimpleXML note: current configuration parsing uses `empty()` on child elements, so marker elements should not be self-closing. Use paired tags with a small text value, as shown below.

```xml
<xml>
    <security>
        <persistence>
            <synchronizer_token secret="change-me">1</synchronizer_token>
        </persistence>

        <csrf secret="change-me" expiration="600">1</csrf>

        <authentication>
            <form dao="App\Security\FormAuthenticationDAO">
                <login
                    page="login"
                    target_success="index"
                    target_failure="login"
                    parameter_username="username"
                    parameter_password="password"
                    parameter_remember_me="remember_me"
                    csrf="csrf">1</login>
                <logout
                    page="logout"
                    target_success="login"
                    target_failure="error">1</logout>
            </form>
        </authentication>

        <authorization>
            <by_dao
                page_dao="App\Security\PageAuthorizationDAO"
                user_dao="App\Security\UserAuthorizationDAO"
                logged_in_callback="forbidden"
                logged_out_callback="login">1</by_dao>
        </authorization>
    </security>
</xml>
```

### `security.persistence`

Required. At least one child driver must be configured.

Supported drivers:

- `session`
  - `parameter_name` optional, default `uid`
  - `expiration` optional
  - `is_http_only` optional, `0` or `1`
  - `is_https_only` optional, `0` or `1`
  - `same_site` optional: `Lax`, `Strict`, or `None`
  - `handler` optional custom session handler class
- `remember_me`
  - `secret` required
  - `parameter_name` optional, default `uid`
  - `expiration` optional, default `86400`
  - `is_http_only` optional, `0` or `1`
  - `is_https_only` optional, `0` or `1`
  - `same_site` optional: `Lax`, `Strict`, or `None`
- `synchronizer_token`
  - `secret` required
  - `expiration` optional, default `3600`
  - `regeneration` optional, default `60`

`Wrapper::getAccessToken()` returns a token only when `synchronizer_token` persistence is configured.

### `security.csrf`

Required.

Attributes:

- `secret` required
- `expiration` optional, defaults to `600` seconds

Form login validates the submitted CSRF parameter against this token. Generate the value for forms with `Wrapper::getCsrfToken()`.

### `security.authentication`

Required. At least one authentication method must be configured.

#### Form Authentication

```xml
<authentication>
    <form dao="App\Security\FormAuthenticationDAO">
        <login page="login" target_success="index" target_failure="login">1</login>
        <logout page="logout" target_success="login" target_failure="error">1</logout>
    </form>
</authentication>
```

`form@dao` is required and must implement [`Lucinda\WebSecurity\DAO\FormAuthentication`](/Users/luciangabrielpopescu/framework/security/src/DAO/FormAuthentication.php).

When form authentication is enabled, pass a [`Lucinda\WebSecurity\DAO\LoginThrottler`](/Users/luciangabrielpopescu/framework/security/src/DAO/LoginThrottler.php) instance as the fourth `Wrapper` constructor argument.

`login` attributes:

- `page` required
- `target_success` required
- `target_failure` required
- `parameter_username` optional, default `username`
- `parameter_password` optional, default `password`
- `parameter_remember_me` optional, default `remember_me`
- `csrf` optional, default `csrf`

`logout` attributes:

- `page` required
- `target_success` required
- `target_failure` required

Successful password verification initially produces `Authentication\ResultStatus::PASSWORD_VERIFIED`; `Wrapper` turns that into `LOGIN_OK` after persistence is updated, unless MFA is configured.

#### OAuth2 Authentication

```xml
<authentication>
    <oauth2
        dao="App\Security\Oauth2AuthenticationDAO"
        logout="logout"
        target_login_success="index"
        target_login_failure="login"
        target_logout_success="login"
        target_logout_failure="error">
        <driver name="github" login="login/github">1</driver>
    </oauth2>
</authentication>
```

`oauth2@dao` is required and must implement [`Lucinda\WebSecurity\DAO\Oauth2Authentication`](/Users/luciangabrielpopescu/framework/security/src/DAO/Oauth2Authentication.php).

Each `driver` requires:

- `name`: the array key used when injecting OAuth2 services into `Wrapper`
- `login`: URI that starts or completes provider login

Inject services as the third `Wrapper` constructor argument:

```php
$wrapper = new Wrapper(
    $xml,
    $request,
    [
        "github" => $githubOauth2Service, // implements Lucinda\WebSecurity\Oauth2Service
    ]
);
```

An OAuth2 service must implement [`Lucinda\WebSecurity\Oauth2Service`](/Users/luciangabrielpopescu/framework/security/src/Oauth2Service.php).

### `security.multi_factor_authentication`

Optional. Current MFA support is TOTP (Google Authenticator).

```xml
<multi_factor_authentication
    dao="App\Security\MultiFactorAuthenticationDAO"
    challenge_route="mfa/challenge"
    setup_route="mfa/setup"
    success_route="index"
    failure_route="mfa/challenge"
    throttled_route="mfa/throttled">
    <totp issuer="My App" code_param="code" period="30" digits="6" window="1">1</totp>
</multi_factor_authentication>
```

`dao` must implement [`Lucinda\WebSecurity\DAO\MultiFactorAuthentication`](/Users/luciangabrielpopescu/framework/security/src/DAO/MultiFactorAuthentication.php).

`totp` attributes:

- `issuer` required
- `code_param` optional, default `code`
- `period` optional, default `30`
- `digits` optional, one of `6`, `7`, `8`; default `6`
- `window` optional, default `1`

## Authorization

`security.authorization` is required. Configure at least one method.

### DAO Authorization

```xml
<authorization>
    <by_dao
        page_dao="App\Security\PageAuthorizationDAO"
        user_dao="App\Security\UserAuthorizationDAO"
        logged_in_callback="forbidden"
        logged_out_callback="login">1</by_dao>
</authorization>
```

Attributes:

- `page_dao` required, class must extend [`Lucinda\WebSecurity\DAO\PageAuthorization`](/Users/luciangabrielpopescu/framework/security/src/DAO/PageAuthorization.php)
- `user_dao` required, class must extend [`Lucinda\WebSecurity\DAO\UserAuthorization`](/Users/luciangabrielpopescu/framework/security/src/DAO/UserAuthorization.php)
- `logged_in_callback` required
- `logged_out_callback` required

### Route Authorization

```xml
<authorization>
    <by_route
        roles_dao="App\Security\UserRolesDAO"
        logged_in_callback="forbidden"
        logged_out_callback="login">1</by_route>
</authorization>

<routes>
    <route id="login" roles="GUEST,USER">1</route>
    <route id="index" roles="USER">1</route>
</routes>
```

Attributes:

- `roles_dao` required, class must implement [`Lucinda\WebSecurity\DAO\UserRoles`](/Users/luciangabrielpopescu/framework/security/src/DAO/UserRoles.php)
- `logged_in_callback` required
- `logged_out_callback` required

When using `by_route`, pass an XML object containing `<routes>` as the fifth `Wrapper` constructor argument.

## Main Contracts

Application code supplies these extension points:

- [`DAO\FormAuthentication`](/Users/luciangabrielpopescu/framework/security/src/DAO/FormAuthentication.php): username/password login and logout
- [`DAO\LoginThrottler`](/Users/luciangabrielpopescu/framework/security/src/DAO/LoginThrottler.php): form login throttling
- [`DAO\Oauth2Authentication`](/Users/luciangabrielpopescu/framework/security/src/DAO/Oauth2Authentication.php): maps provider identities to local users
- [`DAO\OAuth2\UserInformation`](/Users/luciangabrielpopescu/framework/security/src/DAO/Oauth2/UserInformation.php): provider user information
- [`Oauth2Service`](/Users/luciangabrielpopescu/framework/security/src/Oauth2Service.php): provider-specific OAuth2 operations
- [`DAO\MultiFactorAuthentication`](/Users/luciangabrielpopescu/framework/security/src/DAO/MultiFactorAuthentication.php): TOTP setup, secret lookup, and MFA throttling
- [`DAO\PageAuthorization`](/Users/luciangabrielpopescu/framework/security/src/DAO/PageAuthorization.php): maps the requested URI to an application page
- [`DAO\UserAuthorization`](/Users/luciangabrielpopescu/framework/security/src/DAO/UserAuthorization.php): decides whether the current user can access a page
- [`DAO\UserRoles`](/Users/luciangabrielpopescu/framework/security/src/DAO/UserRoles.php): provides roles for route authorization

## Outcomes

`Wrapper::getOutcome()` returns `null` when the request can continue normally. Otherwise it returns one of:

- [`Packets\Security`](/Users/luciangabrielpopescu/framework/security/src/Packets/Security.php)
- [`Packets\MultiFactor`](/Users/luciangabrielpopescu/framework/security/src/Packets/MultiFactor.php)
- [`Packets\Throttling`](/Users/luciangabrielpopescu/framework/security/src/Packets/Throttling.php)

Useful packet methods:

- `getStatus()`
- `getCallback()`
- `getUserID()`
- `Security::getAccessToken()`
- `MultiFactor::getSecret()`
- `MultiFactor::getProvisioningURI()`
- `Throttling::getTimePenalty()`

Status enums:

- [`Security\Authentication\ResultStatus`](/Users/luciangabrielpopescu/framework/security/src/Security/Authentication/ResultStatus.php): `PASSWORD_VERIFIED`, `LOGIN_OK`, `LOGIN_FAILED`, `LOGIN_THROTTLED`, `LOGOUT_OK`, `LOGOUT_FAILED`, `DEFERRED`
- [`Security\Authorization\ResultStatus`](/Users/luciangabrielpopescu/framework/security/src/Security/Authorization/ResultStatus.php): `OK`, `UNAUTHORIZED`, `FORBIDDEN`, `NOT_FOUND`
- [`Security\MultiFactorAuthentication\ResultStatus`](/Users/luciangabrielpopescu/framework/security/src/Security/MultiFactorAuthentication/ResultStatus.php): `NOT_REQUIRED`, `SETUP_REQUIRED`, `REQUIRED`, `SUCCEEDED`, `THROTTLED`, `FAILED`

## Exceptions

Configuration and low-level token failures still throw exceptions:

- [`Configuration\Exception`](/Users/luciangabrielpopescu/framework/security/src/Configuration/Exception.php)
- [`Security\Exception`](/Users/luciangabrielpopescu/framework/security/src/Security/Exception.php)
- token exceptions under [`src/Token`](/Users/luciangabrielpopescu/framework/security/src/Token)
- packet exceptions under [`src/Packets`](/Users/luciangabrielpopescu/framework/security/src/Packets)

## Testing

The repository uses `lucinda/unit-testing`, not PHPUnit.

Run the full suite with:

```bash
php test.php
```

The current suite covers configuration parsing, request/packet value objects, token helpers, persistence drivers, detectors, authentication/authorization services, MFA helpers, and wrapper integration.
