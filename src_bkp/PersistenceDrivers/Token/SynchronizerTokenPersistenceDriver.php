<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\Token\EncryptionException;
use Lucinda\WebSecurity\Token\Exception;
use Lucinda\WebSecurity\Token\SynchronizerToken;
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\WebSecurity\Token\ExpiredException;

/**
 * Encapsulates a PersistenceDriver that employs SynchronizerToken to authenticate users.
 */
class SynchronizerTokenPersistenceDriver extends PersistenceDriver
{
    private int $expirationTime;
    private int $regenerationTime;
    private SynchronizerToken $tokenDriver;

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
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param  int|string $userID Unique user identifier (usually an int)
     * @throws EncryptionException
     */
    public function save(int|string $userID): void
    {
        $this->accessToken = $this->tokenDriver->encode($userID, $this->expirationTime);
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an int) or NULL if none exists.
     * @throws EncryptionException
     * @throws Exception
     */
    public function load(): int|string|null
    {
        if (!$this->accessToken) {
            return null;
        }
        // decode token
        $userID = null;
        try {
            $userID = $this->tokenDriver->decode($this->accessToken, $this->regenerationTime);
        } catch (RegenerationException $e) {
            $userID = $e->getPayload();
            $this->accessToken = $this->tokenDriver->encode($userID, $this->expirationTime);
        } catch (ExpiredException $e) {
            $this->accessToken = null;
            return null;
        }
        return $userID;
    }

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $this->accessToken = "";
    }
}
