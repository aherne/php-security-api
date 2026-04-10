<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;

/**
 * Encapsulates a driver that persists unique user identifier into sessions.
 */
class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
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
     * @param int|string $userID Unique user identifier (usually an int)
     */
    public function save(int|string $userID): void
    {
        session_regenerate_id(true); // OWASP recomments renewing session ID on privilege changes
        $_SESSION[$this->parameterName] = $userID;
        $_SESSION["ip"] = $this->current_ip;
        $_SESSION["time"] = time()+$this->securityOptions->getExpirationTime();
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an int) or NULL if none exists.
     * @throws HijackException
     */
    public function load(): int|string|null
    {
        // start session, using security options if requested
        if (session_id() == "") {
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
            session_start();
        }

        // do nothing if session does not include uid
        if (empty($_SESSION[$this->parameterName])) {
            return null;
        }

        // session hijacking prevention: session id is tied to a single ip
        if ($this->current_ip!=$_SESSION["ip"]) {
            session_regenerate_id(true);
            $_SESSION = [];
            throw new HijackException("Session hijacking attempt!");
        }

        // session fixation prevention: if session is accessed after expiration time, it is invalidated
        if ($this->securityOptions->getExpirationTime() && time()>$_SESSION["time"]) {
            session_regenerate_id(true);
            $_SESSION = [];
            return null;
        }

        // update last time
        $_SESSION["time"] = time()+$this->securityOptions->getExpirationTime();

        return $_SESSION[$this->parameterName];
    }

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $_SESSION = [];
        session_regenerate_id(true);
    }
}
