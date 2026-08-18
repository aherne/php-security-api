<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\WebSecurity\Token\ExpiredException;

/**
 * Encapsulates a PersistenceDriver that employs SynchronizerToken to authenticate users.
 */
final class PersistenceDriver implements \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
{
    private int $expirationTime;
    private int $regenerationTime;
    private SynchronizerToken $tokenDriver;
    protected ?string $accessToken = null;

    /**
     * Creates a persistence driver object.
     *
     * @param string $salt             Strong password to use for crypting.
     * @param string $ip               Value of REMOTE_ADDR attribute, unless ignored.
     * @param int    $expirationTime   Time by which token expires (can be renewed), in seconds.
     * @param int    $regenerationTime Time by which token is renewed, in seconds.
     */
    public function __construct(string $salt, string $ip, int $expirationTime = 3600, int $regenerationTime = 60)
    {
        $this->tokenDriver = new SynchronizerToken($ip, $salt);
        $this->expirationTime = $expirationTime;
        $this->regenerationTime = $regenerationTime;
    }    

    /**
     * Sets access token value based on contents of HTTP authorization header of "bearer" type
     *
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets access token value.
     *
     * @return ?string
     */
    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }


    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param LoggedInUserInfo $authentication Encapsulated persistent authentication
     */
    public function save(LoggedInUserInfo $authentication): void
    {
        $this->accessToken = $this->tokenDriver->encode(serialize($authentication), $this->expirationTime);
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return LoggedInUserInfo|null Encapsulated persistent authentication
     * @throws EncryptionException
     * @throws Exception
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
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $this->accessToken = "";
    }
}
