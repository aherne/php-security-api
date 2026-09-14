<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\Exception as PersistenceException;

/**
 * Persists authentication state in a PHP session with IP and expiration checks
 *
 * Loading starts a session when necessary and refreshes its idle deadline.
 * Saving requires an active session and regenerates its ID. Clearing empties
 * the entire session, not only the authentication entry.
 *
 * @see Wrapper
 * @see \Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo
 */
final class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private string $current_ip;
    private string $parameterName;
    private CookieSecurityOptions $securityOptions;

    /**
     * Creates a session persistence driver without starting a session
     *
     * @param string $parameterName Session entry containing serialized authentication state
     * @param CookieSecurityOptions $securityOptions Cookie attributes and session lifetime settings
     * @param string $ip Client IP for binding, or an empty string when IP binding is disabled
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
     * Stores authentication state in the active session and regenerates its ID
     *
     * Records the client IP and sets a new idle deadline from the configured
     * duration. The old session ID is deleted during regeneration.
     *
     * @param LoggedInUserInfo $authentication Authentication state to persist
     * @throws PersistenceException If the session is inactive or its ID cannot be regenerated
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
     * Restores authentication state from the session
     *
     * Starts the session if necessary. Validates stored metadata, checks the
     * client IP and idle deadline, and refreshes the deadline before restoring
     * the payload. Attempts to clear the entire session for invalid or expired
     * state. A zero configured duration disables the driver's idle expiry check.
     *
     * @return LoggedInUserInfo|null Stored authentication state, or null when absent or expired
     * @throws HijackException If the recorded IP differs from the current IP and cleanup succeeds
     * @throws PersistenceException If session startup, payload validation, or cleanup fails
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
     * Empties the entire active session and regenerates its ID
     *
     * Removes all session entries, including application data unrelated to
     * authentication, and deletes the old session ID during regeneration.
     *
     * @throws PersistenceException If the session is inactive or its ID cannot be regenerated
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
     * Starts a session using the configured cookie security and lifetime settings
     *
     * A non-zero duration also sets the PHP session garbage-collection lifetime.
     *
     * @throws PersistenceException If PHP cannot start the session
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
