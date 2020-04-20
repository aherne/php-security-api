# Web Security API

This API implements common concerns of web security (authentication, authorization, state persistence, csrf prevention) on OWASP guidelines using this series of steps:

- **[configuration](#configuration)**: setting up an XML file where web security is configured
- **[setting request information](#setting-request-information)**: setting request information in a [Lucinda\WebSecurity\Request](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Request.php) instance
- **[setting oauth2 drivers](#setting-oauth2-drivers)**: (optional) setting oauth2 drivers available for authentication in a list of [Lucinda\WebSecurity\Authentication\OAuth2\Driver](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/Driver.php) instances
- **[getting results](#getting-results)**: creating a [Lucinda\WebSecurity\Wrapper](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Wrapper.php) instance based on above and use it to get logged in user id, access token (for stateless apps) or csrf token (for form logins)

API is fully PSR-4 compliant, only requiring PHP7.1+ interpreter and SimpleXML + OpenSSL extensions. To quickly see how it works, check:

- **[installation](#installation)**: describes how to install API on your computer, in light of steps above
- **[unit tests](#unit-tests)**: API has 100% Unit Test coverage, using [UnitTest API](https://github.com/aherne/unit-testing) instead of PHPUnit for greater flexibility
- **[example](https://github.com/aherne/php-security-api/blob/v3.0.0/tests/WrapperTest.php)**: shows a deep example of API functionality based on unit test for [Lucinda\WebSecurity\Wrapper](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Wrapper.php)

## Configuration

To configure this API you must have a XML with following tags inside:

- **[security](#security)**: (mandatory) configures the api
- **[users](#users)**: (optional) required only if authentication is by XML (access control list)
- **[routes](#routes)**: (optional) required only if authorization is by XML (access control list)

### Security

Maximal syntax of this tag is:

```xml
<security dao_path="...">
    <csrf secret="..." expiration="..."/>
    <persistence>
        <session parameter_name="..." expiration="..." is_http_only="..." is_https_only="..." ignore_ip="..." handler="..."/>
        <remember_me secret="..." parameter_name="..."  expiration="..." is_http_only="..." is_https_only="..."/>
        <synchronizer_token secret="..." expiration="..." regeneration="..."/>
        <json_web_token secret="..." expiration="..." regeneration="..."/>
    </persistence>
    <authentication>
        <form dao="..." throttler="...">
            <login page="..." target="..." parameter_username="..." parameter_password="..."  parameter_rememberMe="..." />
            <logout page="..." target="..."/>
        </form>
        <oauth2 dao="..." target="..." login="..." logout="..."/>
    </authentication>
    <authorization>
        <by_dao page_dao="..." user_dao="..." logged_in_callback="..." logged_out_callback="..."/>
        <by_route logged_in_callback="..." logged_out_callback="..."/>
    </authorization>
</security>
```

Where:

- **security**: (mandatory) holds global web security policies. 
    - *dao_path*: location to DAO classes (required if authentication/authorization use database)    
    - **csrf**: (mandatory) holds settings necessary to produce an anti-CSRF token (useful to sign authentication with)
        - *secret*: (mandatory) password to use in encrypting csrf token (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
        - *expiration*: (optional) seconds until token expires. If not set, token will expire in 10 minutes.
    - **persistence** (mandatory) holds one or more mechanisms useful to preserve logged in state across requests (at least one is mandatory!)
        - **session**: (optional) configures persistence of logged in state by HTTP session
            - *parameter_name*: (optional) name of $_SESSION parameter that will store logged in state. If not set, "uid" is assumed.
            - *expiration*: (optional) seconds until session expires. If not set, session will expire as server-default.
            - *is_http_only*: (optional) whether or not to set session cookie as HttpOnly (can be 0 or 1; 0 is default).
            - *is_https_only*: (optional) whether or not to set session cookie as HTTPS only (can be 0 or 1; 0 is default).
            - *handler*: (optional) name of class (incl. namespace or relative path) implementing [SessionHandlerInterface](https://www.php.net/manual/en/class.sessionhandlerinterface.php) to which session handling will be delegated to. 
        - **remember_me**: (optional) configures persistence of logged in state by HTTP remember me cookie
            - *secret*: (mandatory) password to use in encrypting cookie (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
            - *parameter_name*: (optional) name of $_COOKIE parameter that will store logged in state. If not set, "uid" is assumed.
            - *expiration*: (optional) seconds until cookie expires. If not set, cookie will expire in one day.
            - *is_http_only*: (optional) whether or not to set cookie as HttpOnly (can be 0 or 1; 0 is default).
            - *is_https_only*: (optional) whether or not to set cookie as HTTPS only (can be 0 or 1; 0 is default).
        - **synchronizer_token**: (optional) configures persistence of logged in state by signing every request with a synchronizer token
            - *secret*: (mandatory) password to use in encrypting token (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
            - *expiration*: (optional) seconds until token expires. If not set, token will expire in 1 hour.
            - *regeneration*: (optional) seconds from the moment token was created until it needs to regenerate on continuous usage. If not set, token will be regenerated in 1 minute.
        - **json_web_token**: (optional) configures persistence of logged in state by signing every request with a json web token
            - *secret*: (mandatory) password to use in encrypting token (use: [Lucinda\WebSecurity\Token\SaltGenerator](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/SaltGenerator.php))
            - *expiration*: (optional) seconds until token expires. If not set, token will expire in 1 hour.
            - *regeneration*: (optional) seconds from the moment token was created until it needs to regenerate on continuous usage. If not set, token will be regenerated in 1 minute.
    - **authentication**: (mandatory) holds one or more mechanisms to authenticate (at least one is mandatory!)
        - **form**: (optional) configures authentication via form. If no *dao* attribute is set, authentication is done via XML and [users](#users) tag is required!
            - *dao*: (optional) name of class (incl. namespace or subpath) implementing [Lucinda\WebSecurity\Authentication\DAO\UserAuthenticationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/DAO/UserAuthenticationDAO.php) that performs form authentication in database, found in folder set by *dao_path* attribute above. [1]
            - *throttler*: (optional) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authentication\Form\LoginThrottler](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/Form/LoginThrottler.php) that performs login throttling prevention, found in folder set by *dao_path* attribute above
            - **login**: (optional) configures login
                - *page*: (optional) page that performs login operation (all requests to this page will pass through this filter), also one to redirect back if login is unsuccessful. If none, then "login" is implicitly used.
                - *target*: (optional) destination page after successful login. If none, then "index" is implicitly used.
                - *parameter_username*: (optional) name of $_POST parameter username will be submitted as. If none, then "username" is implicitly used.
                - *parameter_password*: (optional) name of $_POST parameter password will be submitted as. If none, then "password" is implicitly used.
                - *parameter_rememberMe*: (optional) name of $_POST parameter that activates "remember me" option (value can be 0 or 1). If none, then "remember_me" is implicitly used.
            - **logout**: (optional) configures logout
                - *page*: (optional) page that performs logout operation (all requests to this page will pass through this filter). If none, then "logout" is implicitly used.
                - *target*: (optional) destination page after successful or unsuccessful logout. If none, then "login" is implicitly used.
        - **oauth2**: (optional) configures authentication via oauth2 provider
            - *dao*: (mandatory) name of class (incl. namespace or subpath) implementing [Lucinda\WebSecurity\Authentication\OAuth2\VendorAuthenticationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/VendorAuthenticationDAO.php) that saves results of authentication in database, found in folder set by *dao_path* attribute above
            - *target*: (optional) destination page after successful login. If none, then "index" is implicitly used.
            - *login*: (optional) generic page where login by provider option is available. If none, then "login" is implicitly used. 
            - *logout*: (optional) page that performs logout operation. If none, then "logout" is implicitly used.
    - **authorization**: (mandatory) holds a single mechanism to authorize requests (at least one is mandatory!)
        - **by_dao**: (optional) configures authorization by database
            - *page_dao*: (mandatory) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authorization\DAO\UserAuthorizationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authorization/DAO/UserAuthorizationDAO.php) that checks user rights in database, found in folder set by *dao_path* attribute above
            - *user_dao*: (mandatory) name of class (incl. namespace or subpath) extending [Lucinda\WebSecurity\Authorization\DAO\PageAuthorizationDAO](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authorization/DAO/PageAuthorizationDAO.php) that checks page rights in database, found in folder set by *dao_path* attribute above
            - *logged_in_callback*: (optional) callback page for authenticated users when authorization fails. If none, then "index" is implicitly used.
            - *logged_out_callback*: (optional) callback page for guest users when authorization fails. If none, then "login" is implicitly used.
        - **by_route**: (optional) configures authorization by XML, in which case [routes](#routes) tag is required. [1]
            - *logged_in_callback*: (optional) callback page for authenticated users when authorization fails. If none, then "index" is implicitly used.
            - *logged_out_callback*: (optional) callback page for guest users when authorization fails. If none, then "login" is implicitly used.

For examples of XMLs, check [WrapperTest](https://github.com/aherne/php-security-api/blob/v3.0.0/tests/WrapperTest.php) @ unit tests!

Notes:
(1) If authorization is **by_route**, **authentication** is **form** with a *dao* attribute, then class referenced there must also implement [Lucinda\WebSecurity\Authorization\UserRoles](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authorization/UserRoles.php)

### Users

This tag is required if XML authentication (**form** tag is present and has no *dao* attribute) + authorization (**by_route** tag is present) are used. Syntax is:


```xml
<users roles="...">
    <user id="..." username="..." password="..." roles="..."/>
    ...
</security>
```

Where:

- **users**: (mandatory) holds list of site users, each identified by a **user** tag
    - *roles*: (mandatory) holds list of roles guests (non-logged in users) belong to, separated by commas
    - **user**: (mandatory) holds information about a single user
        - *id*: (mandatory) holds unique user identifier (eg: 1)
        - *username*: (optional) holds user's username (eg: john_doe). Mandatory for XML authentication!
        - *password*: (optional) holds user's password hashed using [password_hash](https://www.php.net/manual/en/function.password-hash.php) (eg: value of ```php password_hash("doe", PASSWORD_BCRYPT) ```).   Mandatory for XML authentication!
        - *roles*: (optional) holds list of roles user belongs to, separated by commas (eg: USERS, ADMINISTRATORS). Mandatory for XML authentication+authorization

If no user is detected in list above, GUEST role is automatically assumed!

### Routes

This tag is required if XML authorization (**by_route** tag is present) is used. Syntax is:


```xml
<routes roles="...">
    <route url="..." roles="..."/>
    ...
</routes>
```

Where:

- **routes**: (mandatory) holds list of site routes, each identified by a **route** tag
    - *roles*: (mandatory) holds list of roles all pages are assumed to belong by default to, separated by commas (eg: GUEST)
    - **route**: (mandatory) holds policies about a specific route
        - *url*: (mandatory) page relative url (eg: administration)
        - *roles*: (mandatory) holds list of roles page is associated to, separated by commas (eg: USERS, ADMINISTRATORS)

## Setting request information

Both authentication and authorization require knowledge of request to be handled. All of this is encapsulated by a [Lucinda\WebSecurity\Request](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Request.php) instance with following public methods:

| Method | Arguments | Returns | Description |
| --- | --- | --- | --- |
| setIpAddress | string $value | void | Sets ip address used by client (eg: value of $_SERVER["REMOTE_ADDR"]) |
| setContextPath | string $value | void | Sets context path that prefixes page requested by client (eg: prefix of $_SERVER["REQUEST_URI"]) |
| setUri | string $value | void | Sets page/resource requested by client without trailing slash (eg: suffix of $_SERVER["REQUEST_URI"])  |
| setMethod | string $value | void | Sets HTTP method used by client in page request (eg: value of $_SERVER["REQUEST_METHOD"]) |
| setParameters | array $value | void | Sets parameters sent by client as GET/POST along with request (eg: value of $_REQUEST) |
| setAccessToken | string $value | void | Sets access token detected from client headers for stateless login (eg:  suffix of $_SERVER["HTTP_AUTHORIZATION"]) |
| getIpAddress | string $value | void | Gets ip address used by client (eg: value of $_SERVER["REMOTE_ADDR"]) |
| getContextPath | string $value | void | Gets context path that prefixes page requested by client (eg: prefix of $_SERVER["REQUEST_URI"]) |
| getUri | string $value | void | Gets page/resource requested by client without trailing slash (eg: suffix of $_SERVER["REQUEST_URI"])  |
| getMethod | string $value | void | Gets HTTP method used by client in page request (eg: value of $_SERVER["REQUEST_METHOD"]) |
| getParameters | array $value | void | Gets parameters sent by client as GET/POST along with request (eg: value of $_REQUEST) |
| getAccessToken | string $value | void | Gets access token detected from client headers for stateless login (eg:  Bearer value of $_SERVER["HTTP_AUTHORIZATION"]) |

Usage example:

```php
$request = new Lucinda\WebSecurity\Request();
$request->setIpAddress($_SERVER["REMOTE_ADDR"]);
$request->setUri($_SERVER["REQUEST_URI"]!="/"?substr($_SERVER["REQUEST_URI"],1):"index");
$request->setMethod($_SERVER["REQUEST_METHOD"]);
$request->setParameters($_POST);
$request->setAccessToken(isset($_SERVER["HTTP_AUTHORIZATION"]) && stripos($_SERVER["HTTP_AUTHORIZATION"], "Bearer ")===0?trim(substr($_SERVER["HTTP_AUTHORIZATION"], 7)):"");
```

## Setting OAuth2 drivers

Authentication by OAuth2 vendors (eg: Facebook) is supported by this API as long as an external source (developer) implements interface [Lucinda\WebSecurity\Authentication\OAuth2\Driver](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/Driver.php) for each vendor that's going to be used. Interface defines following methods:

| Method | Arguments | Returns | Description |
| --- | --- | --- | --- |
| getAuthorizationCode | string $state | string | Gets URL to redirect to vendor in order for latter to send back an autorization code |
| getAccessToken | string $authorizationCode | string | Asks vendor to exchange authorization code with an access token and returns it |
| getUserInformation | string $accessToken | [Lucinda\WebSecurity\Authentication\OAuth2\UserInformation](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/UserInformation.php) | Uses access token to get logged in user information from vendor |
| getCallbackUrl | void | string | Gets login route of current OAuth2 provider (eg: login/facebook) |
| getVendorName | void | string | Gets name of current OAuth2 provider (eg: facebook) |


## Getting Results

Once all above information is compiled, one can finally use this API to authenticate and authorize by calling [Lucinda\WebSecurity\Wrapper](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Wrapper.php), which defines following public methods:

| Method | Arguments | Returns | Description |
| --- | --- | --- | --- |
| __construct | \SimpleXMLElement $xml, [Lucinda\WebSecurity\Request](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Request.php) $request, [Lucinda\WebSecurity\Authentication\OAuth2\Driver](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/Driver.php)[] $oauth2Drivers = [] | void | Performs authentication and authorization of request based on arguments |
| getUserID | void | mixed | Gets logged in user id (integer or string) |
| getCsrfToken | void | string | Gets anti-CSRF token to send as "csrf" POST parameter on form login and "state" GET parameter in oauth2 authorization code requests |
| getAccessToken | void | string | Gets access token to sign stateless requests with as Bearer HTTP_AUTHORIZATION header (applies if "synchronizer token" or "json web token" persistence is used) |


### Handling SecurityPacket

If authentication/authorization reached a point where request needs to be redirected, constructor throws a [Lucinda\WebSecurity\SecurityPacket](https://github.com/aherne/php-security-api/blob/v3.0.0/src/SecurityPacket.php), which defines following methods relevant to developers:

| Method | Arguments | Returns | Description |
| --- | --- | --- | --- |
| getAccessToken | void | string | Gets access token to sign stateless requests with as Bearer HTTP_AUTHORIZATION header (applies if "synchronizer token" or "json web token" persistence is used) |
| getCallback | void | integer/string | Gets URI inside application to redirect to in case of successful/insuccessful authentication or insuccessful authorization |
| getStatus | void | string | Gets authentication/authorization status code (see below) |
| getTimePenalty | void | integer | Sets number of seconds client will be banned from authenticating as anti-throttling measure |

Values of *getStatus* describe authentication/authorization outcome and suggest :

- *login_ok*: login was successful and a redirection to logged in homepage is required
- *login_failed*: login failed and a redirection to login page is required
- *logout_ok*: logout was successful and a redirection to login page is required
- *logout_failed*: logout was unsuccessful and a redirection to login page is required
- *not_found*: route requested by client not known by any access policy
- *redirect*: redirection to OAuth2 vendor's authorization request page is required
- *unauthorized*: route requested by client requires authentication, thus redirection to login page is required
- *forbidden*: route requested by client is forbidden to current logged in user, thus a redirection to logged in homepage is required

Developers of non-stateless applications are supposed to handle this exception with something like:

```php
try {
	// sets $xml and $request
	$object = new Lucinda\WebSecurity\Wrapper($xml, $request);
	// operate with $object to retrieve information
} catch (Lucinda\WebSecurity\SecurityPacket $e) {
	header("Location: ".$e->getCallback()."?status=".$e->getStatus()."&penalty=".((integer) $e->getTimePenalty()));
	exit();
}
```

Developers of stateless web service applications, however, are supposed to handle this exception with something like:

```php
try {
	// sets $xml and $request
	$object = new Lucinda\WebSecurity\Wrapper($xml, $request);
	// use $object to produce a response
} catch (Lucinda\WebSecurity\SecurityPacket $e) {
	echo json_encode(["status"=>$e->getStatus(), "callback"=>$e->getCallback(), "penalty"=>(integer) $e->getTimePenalty(), "access_token"=>$e->getAccessToken()]);
	exit();
	// front end will handle above code and make a redirection
}
```
### Handling other exceptions

[Lucinda\WebSecurity\Wrapper](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Wrapper.php) may also throw:

- [Lucinda\WebSecurity\Authentication\Form\Exception](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/Form/Exception.php): when login form is posted with wrong parameters names
- [Lucinda\WebSecurity\Authentication\OAuth2\Exception](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Authentication/OAuth2/Exception.php): when OAuth2 provider answers with an error to authorization code or access token requests
- [Lucinda\WebSecurity\PersistenceDrivers\Session\HijackException](https://github.com/aherne/php-security-api/blob/v3.0.0/src/PersistenceDrivers/Session/HijackException.php): when user id in session is associated to a different IP address
- [Lucinda\WebSecurity\Token\EncryptionException](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/EncryptionException.php): when token could not be decrypted
- [Lucinda\WebSecurity\Token\Exception](https://github.com/aherne/php-security-api/blob/v3.0.0/src/Token/Exception.php): when CSRF token is invalid or missing as "csrf" POST param @ form login or "state" GET param @ oauth2 authorization code response 
- [Lucinda\WebSecurity\ConfigurationException](https://github.com/aherne/php-security-api/blob/v3.0.0/src/ConfigurationException.php): when XML is misconfigured, referenced classes are not found or not fitting expected pattern

They can be handled as following:

```php
try {
	// sets $xml and $request
	$object = new Lucinda\WebSecurity\Wrapper($xml, $request);
	// process $object
} catch (Lucinda\WebSecurity\SecurityPacket $e) {
	// handle security packet as above
} catch (Lucinda\WebSecurity\Authentication\Form\Exception $e) {
	// respond with a 400 Bad Request HTTP status (it's either foul play or misconfiguration)
} catch (Lucinda\WebSecurity\PersistenceDrivers\Session\HijackException $e) {
	// respond with a 400 Bad Request HTTP status (it's always foul play)
} catch (Lucinda\WebSecurity\Token\EncryptionException $e) {
	// respond with a 400 Bad Request HTTP status (it's always foul play)
} catch (Lucinda\WebSecurity\Token\Exception $e) {
	// respond with a 400 Bad Request HTTP status (it's either foul play or misconfiguration)
} catch (Lucinda\WebSecurity\ConfigurationException $e) {
	// show stack trace and exit (it's misconfiguration)
} catch (Lucinda\WebSecurity\Authentication\OAuth2\Exception $e) {
	// handle as you want (error received from OAuth2 vendor usually from user's decision not to approve your access)
}
```

## Installation

First choose a folder, associate it to a domain then write this command in its folder using console:

```console
composer require lucinda/security
```

Then create a *configuration.xml* file holding configuration settings (see [configuration](#configuration) above) and a *index.php* file (see [getting results](#getting-results) above) in project root with following code:

```php
require(__DIR__."/vendor/autoload.php");

$request = new Lucinda\WebSecurity\Request();
$request->setIpAddress($_SERVER["REMOTE_ADDR"]);
$request->setUri($_SERVER["REQUEST_URI"]!="/"?substr($_SERVER["REQUEST_URI"],1):"index");
$request->setMethod($_SERVER["REQUEST_METHOD"]);
$request->setParameters($_POST);
$request->setAccessToken(isset($_SERVER["HTTP_AUTHORIZATION"]) && stripos($_SERVER["HTTP_AUTHORIZATION"], "Bearer ")===0?trim(substr($_SERVER["HTTP_AUTHORIZATION"], 7)):"");

try {
	// sets $xml and $request
	$object = new Lucinda\WebSecurity\Wrapper(simplexml_load_file("configuration.xml"), $request);
	// operate with $object to retrieve information
} catch (Lucinda\WebSecurity\SecurityPacket $e) {
	header("Location: ".$e->getCallback()."?status=".$e->getStatus()."&penalty=".((integer) $e->getTimePenalty()));
	exit();
}

```

Then make this file a bootstrap and start developing MVC pattern on top:

```
RewriteEngine on
RewriteRule ^(.*)$ index.php
```

## Unit Tests

For tests and examples, check following files/folders in API sources:

- [test.php](https://github.com/aherne/php-security-api/blob/v3.0.0/test.php): runs unit tests in console
- [unit-tests.xml](https://github.com/aherne/php-security-api/blob/v3.0.0/unit-tests.xml): sets up unit tests
- [tests](https://github.com/aherne/php-security-api/tree/v3.0.0/tests): unit tests for classes from [src](https://github.com/aherne/php-security-api/tree/v3.0.0/src) folder

