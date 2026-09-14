<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\WebSecurity\Token\ExpiredException;

/**
 * Encodes and restores authentication state using an encrypted bearer token
 *
 * The caller supplies the incoming token and retrieves the current token
 * after loading or saving. This driver does not read request headers or
 * write response headers. It renews eligible tokens while loading.
 *
 * @see Wrapper
 * @see \Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo
 */
final class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private int $expirationTime;
    private int $regenerationTime;
    private SynchronizerToken $tokenDriver;
    protected ?string $accessToken = null;

    /**
     * Creates a bearer-token persistence driver without issuing a token
     *
     * @param string $salt Secret used to derive the token encryption key
     * @param string $ip Client IP for binding, or an empty string when IP binding is disabled
     * @param int $expirationTime Lifetime in seconds for newly issued tokens
     * @param int $regenerationTime Token age threshold in seconds for renewal; zero disables age-based renewal
     */
    public function __construct(string $salt, string $ip, int $expirationTime = 3600, int $regenerationTime = 60)
    {
        $this->tokenDriver = new SynchronizerToken($ip, $salt);
        $this->expirationTime = $expirationTime;
        $this->regenerationTime = $regenerationTime;
    }    

    /**
     * Supplies the incoming authentication bearer token for later loading
     *
     * Stores the value without validating it. The caller extracts the token
     * from the request; the Authorization scheme prefix is not part of it.
     *
     * @param string $accessToken Authentication bearer token without the Bearer prefix
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets the current authentication bearer token
     *
     * Loading may renew the token, and saving replaces it. The caller can
     * return the current value to the client. Treat it as a credential and
     * exclude it from logs.
     *
     * @return string|null Current token, an empty string after clear(), or null before assignment or after expiry
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }


    /**
     * Encodes authentication state into a new bearer token
     *
     * Replaces the current token without sending it to the client.
     * The new value is available through getAccessToken().
     *
     * @param LoggedInUserInfo $authentication Authentication state to persist
     * @throws Exception If the token payload cannot be encoded
     * @throws EncryptionException If token encryption fails
     */
    public function save(LoggedInUserInfo $authentication): void
    {
        $this->accessToken = $this->tokenDriver->encode(serialize($authentication), $this->expirationTime);
    }

    /**
     * Restores authentication state and renews an eligible bearer token
     *
     * Checks token integrity, IP binding, and expiration. An expired token is
     * discarded and yields null. A still-valid token older than the renewal
     * threshold is replaced; retrieve that value through getAccessToken().
     *
     * @return LoggedInUserInfo|null Stored authentication state, or null when no token is supplied or it has expired
     * @throws Exception If token validation or renewal encoding fails
     * @throws EncryptionException If cryptographic processing fails or the restored payload is not authentication state
     */
    public function load(): ?LoggedInUserInfo
    {
        if (!$this->accessToken) {
            return null;
        }
        // decode token
        $userInfo = null;
        try {
            $userInfo = $this->tokenDriver->decode($this->accessToken, $this->regenerationTime);
        } catch (RegenerationException $e) {
            $userInfo = $e->getPayload();
            $this->accessToken = $this->tokenDriver->encode($userInfo, $this->expirationTime);
        } catch (ExpiredException $e) {
            $this->accessToken = null;
            return null;
        }
        
        $user = unserialize($userInfo, ["allowed_classes" => [LoggedInUserInfo::class]]);
        if (!$user instanceof LoggedInUserInfo) {
            throw new EncryptionException("Invalid authentication payload!");
        }

        return $user;
    }

    /**
     * Removes the current token from this driver instance
     *
     * Sets the current value to an empty string. This does not revoke copies
     * of previously issued tokens or remove a token stored by the client.
     */
    public function clear(): void
    {
        $this->accessToken = "";
    }
}
