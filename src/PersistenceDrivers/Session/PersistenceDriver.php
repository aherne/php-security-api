<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\Exception as PersistenceException;

/**
 * Encapsulates a driver that persists unique user identifier into sessions.
 */
final class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private string $current_ip;
    private string $parameterName;
    private CookieSecurityOptions $securityOptions;

    /**
     * Creates a persistence driver object.
     *
     * @param string                $parameterName   Name of SESSION parameter that holds unique user identifier.
     * @param CookieSecurityOptions $securityOptions
     * @param string                $ip              Value of REMOTE_ADDR parameter, unless ignored.
     */
    public function __construct(
        string $parameterName,
        CookieSecurityOptions $securityOptions,
        string $ip=""
    ) {
        $this->current_ip = $ip;
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
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new PersistenceException("Cannot save authentication into an inactive session!");
        }

        if (!session_regenerate_id(true)) {
            throw new PersistenceException("Unable to regenerate session ID!");
        }
        
        $_SESSION[$this->parameterName] = serialize($authentication);
        $_SESSION["ip"] = $this->current_ip;
        $_SESSION["time"] = time()+$this->securityOptions->getExpirationTime();
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return ?LoggedInUserInfo Unique user identifier (usually an int) or NULL if none exists.
     * @throws HijackException
     */
    public function load(): ?LoggedInUserInfo
    {
        // start session, using security options if requested
        if (session_status() !== PHP_SESSION_ACTIVE) {
            $this->start();
        }

        // do nothing if session does not include uid
        if (empty($_SESSION[$this->parameterName])) {
            return null;
        }

        if (
            !is_string($_SESSION[$this->parameterName])
            || !array_key_exists("ip", $_SESSION)
            || !is_string($_SESSION["ip"])
            || !array_key_exists("time", $_SESSION)
            || !is_int($_SESSION["time"])
        ) {
            $this->clear();
            throw new PersistenceException("Session metadata is invalid");
        }

        // session hijacking prevention: session id is tied to a single ip
        if ($this->current_ip!=$_SESSION["ip"]) {
            $this->clear();
            throw new HijackException("Session hijacking attempt!");
        }

        // session fixation prevention: if session is accessed after expiration time, it is invalidated
        if ($this->securityOptions->getExpirationTime() && time()>$_SESSION["time"]) {
            $this->clear();
            return null;
        }

        // update last time
        $_SESSION["time"] = time()+$this->securityOptions->getExpirationTime();

        try {
            $result = @unserialize(
                $_SESSION[$this->parameterName],
                ["allowed_classes" => [LoggedInUserInfo::class]]
                );
        } catch (\Throwable $exception) {
            $this->clear();

            throw new PersistenceException(
                "Session data is invalid",
                0,
                $exception
            );
        }
        
        if (!$result instanceof LoggedInUserInfo) {
            $this->clear();
            throw new PersistenceException("Session data is invalid");
        }
        return $result;
    }

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            throw new PersistenceException(
                "Cannot clear an inactive session!"
            );
        }

        $_SESSION = [];

        if (!session_regenerate_id(true)) {
            throw new PersistenceException(
                "Unable to regenerate session ID!"
            );
        }
    }

    /**
     * Starts session
     * 
     * @throws PersistenceException
     * @return void
     */
    private function start(): void
    {
        $cookieParameters = [];
        $cookieParameters["samesite"] = $this->securityOptions->getSameSite()->value;
        if ($this->securityOptions->isHttpOnly()) {
            $cookieParameters["httponly"] = true;
        }
        if ($this->securityOptions->isSecure()) {
            $cookieParameters["secure"] = true;
        }
        if ($expirationTime = $this->securityOptions->getExpirationTime()) {
            $cookieParameters["lifetime"] = $expirationTime;
            ini_set("session.gc_maxlifetime", (string) $expirationTime);
        }
        session_set_cookie_params($cookieParameters);
        if (session_status() !== PHP_SESSION_ACTIVE) {
            if (!session_start()) {
                throw new PersistenceException("Unable to start session!");
            }
        }
    }
}
