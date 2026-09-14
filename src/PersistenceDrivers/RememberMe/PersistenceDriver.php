<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\ExpiredException;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\PersistenceDrivers\Exception as PersistenceException;

/**
 * Persists authentication state in an encrypted remember-me cookie
 *
 * Serializes authentication state into an expiring token bound to the
 * configured client IP. Writes queue cookie response headers and update
 * the current request's cookie array.
 *
 * @see Wrapper
 * @see \Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo
 */
final class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private SynchronizerToken $token;

    private string $parameterName;
    private CookieSecurityOptions $securityOptions;

    /**
     * Creates a remember-me persistence driver without issuing a cookie
     *
     * @param string $salt Secret used to derive the token encryption key
     * @param string $parameterName Cookie name containing the encrypted authentication state
     * @param CookieSecurityOptions $securityOptions Cookie attributes and lifetime in seconds
     * @param string $ip Client IP for binding, or an empty string when IP binding is disabled
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
     * Encodes authentication state and queues the remember-me cookie
     *
     * Uses the configured duration for both token and cookie expiration.
     * Response headers must still be writable.
     *
     * @param LoggedInUserInfo $authentication Authentication state to persist
     * @throws \Lucinda\WebSecurity\Token\Exception If the token payload cannot be encoded
     * @throws EncryptionException If token encryption fails
     * @throws PersistenceException If the cookie header cannot be queued
     */
    public function save(LoggedInUserInfo $authentication): void
    {
        $token = $this->token->encode(serialize($authentication), $this->securityOptions->getExpirationTime());
        $this->registerCookie($token, time()+$this->securityOptions->getExpirationTime());
    }

    /**
     * Restores authentication state from the remember-me cookie
     *
     * Expired cookies are cleared and yield null if cleanup succeeds. Other
     * caught decoding failures also trigger cookie cleanup before rethrowing.
     * A cleanup failure may replace the original exception.
     *
     * @return LoggedInUserInfo|null Stored authentication state, or null when absent or expired
     * @throws EncryptionException If decryption fails or the restored payload is not authentication state
     * @throws \Lucinda\WebSecurity\Token\Exception If token validation fails for a reason other than expiry
     * @throws PersistenceException If an invalid or expired cookie cannot be cleared
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
     * Expires the remember-me cookie and removes it from the request cookie array
     *
     * Queues a deletion header; it does not revoke copies of previously issued
     * tokens held elsewhere. Response headers must still be writable.
     *
     * @throws PersistenceException If the cookie deletion header cannot be queued
     */
    public function clear(): void
    {
        $this->registerCookie("", time()-3600);
    }

    /**
     * Queues a cookie header and updates the current request's cookie array
     *
     * An empty token removes the entry from the cookie array after the header
     * is queued. The timestamp controls expiration in the browser.
     *
     * @param string $token Encrypted authentication token, or an empty string for deletion
     * @param int $time Cookie expiration as a Unix timestamp in seconds
     * @throws PersistenceException If the cookie header cannot be queued
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
