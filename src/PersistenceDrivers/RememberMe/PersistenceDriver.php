<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\ExpiredException;

/**
 * Encapsulates a driver that persists unique user identifier into a crypted "remember me" cookie variable.
 */
class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
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
     * @param  int|string $userID Unique user identifier (usually an int)
     * @throws EncryptionException
     */
    public function save(int|string $userID): void
    {
        $token = $this->token->encode($userID, $this->securityOptions->getExpirationTime());
        $this->registerCookie($token, time()+$this->securityOptions->getExpirationTime());
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an int) or NULL if none exists.
     * @throws \Exception
     */
    public function load(): int|string|null
    {
        if (empty($_COOKIE[$this->parameterName])) {
            return null;
        }

        try {
            return $this->token->decode($_COOKIE[$this->parameterName]);
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
        setcookie(
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
        if ($token === "") {
            unset($_COOKIE[$this->parameterName]);
        } else {
            $_COOKIE[$this->parameterName] = $token;
        }
    }
}
