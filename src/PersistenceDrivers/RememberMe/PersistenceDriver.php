<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\ExpiredException;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\PersistenceDrivers\Exception as PersistenceException;

/**
 * Encapsulates a driver that persists unique user identifier into a crypted "remember me" cookie variable.
 */
final class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private SynchronizerToken $token;

    private string $parameterName;
    private CookieSecurityOptions $securityOptions;

    /**
     * Creates a persistence driver object.
     *
     * @param string                $salt            Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param string                $parameterName   Name of SESSION parameter that holds cypted unique user identifier.
     * @param CookieSecurityOptions $securityOptions
     * @param string                $ip              Value of REMOTE_ADDR attribute, unless ignored.
     */
    public function __construct(
        string $salt,
        string $parameterName,
        CookieSecurityOptions $securityOptions,
        string $ip=""
    ) {
        $this->token = new SynchronizerToken($ip, $salt);
        $this->parameterName = $parameterName;
        $this->securityOptions = $securityOptions;
    }

    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param LoggedInUserInfo $authentication Encapsulated persistent authentication
     */
    public function save(LoggedInUserInfo $authentication): void
    {
        $token = $this->token->encode(serialize($authentication), $this->securityOptions->getExpirationTime());
        $this->registerCookie($token, time()+$this->securityOptions->getExpirationTime());
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return LoggedInUserInfo|null Encapsulated persistent authentication
     */
    public function load(): ?LoggedInUserInfo
    {
        if (empty($_COOKIE[$this->parameterName])) {
            return null;
        }

        try {
            $userInfo = $this->token->decode($_COOKIE[$this->parameterName]);
            $user = unserialize($userInfo, ["allowed_classes" => [LoggedInUserInfo::class]]);
            if (!$user instanceof LoggedInUserInfo) {
                throw new EncryptionException("Invalid authentication payload!");
            }
            return $user;
        } catch (\Exception $e) {
            // delete bad cookie
            $this->registerCookie("", time()-3600);
            // rethrow exception, unless it's token expired
            if ($e instanceof ExpiredException) {
                return null;
            } else {
                throw $e;
            }
        }
    }

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $this->registerCookie("", time()-3600);
    }

    /**
     * Saves cookie header
     * 
     * @param string $token
     * @param int $time
     * @return void
     */
    private function registerCookie(string $token, int $time): void
    {
        $success = setcookie(
            $this->parameterName,
            $token,
            [
                "expires" => $time,
                "path" => "/",
                "domain" => "",
                "secure" => $this->securityOptions->isSecure(),
                "httponly" => $this->securityOptions->isHttpOnly(),
                "samesite" => $this->securityOptions->getSameSite()->value
            ]
        );
        if (!$success) {
            throw new PersistenceException("Unable to save remember-me cookie");
        }
        if ($token === "") {
            unset($_COOKIE[$this->parameterName]);
        } else {
            $_COOKIE[$this->parameterName] = $token;
        }
    }
}
