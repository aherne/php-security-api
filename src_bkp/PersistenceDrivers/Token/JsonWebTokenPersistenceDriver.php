<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Token;

use Lucinda\WebSecurity\Token\JsonWebToken;
use Lucinda\WebSecurity\Token\RegenerationException;
use Lucinda\WebSecurity\Token\ExpiredException;
use Lucinda\WebSecurity\Token\JsonWebTokenPayload;

/**
 * Encapsulates a PersistenceDriver that uses JsonWebToken to authenticate users.
 */
class JsonWebTokenPersistenceDriver extends PersistenceDriver
{
    private int $expirationTime;
    private int $regenerationTime;
    private JsonWebToken $tokenDriver;

    /**
     * Creates a persistence driver object.
     *
     * @param string $salt             Strong password to use for crypting. (Check: http://randomkeygen.com/)
     * @param int    $expirationTime   Time by which token expires (can be renewed), in seconds.
     * @param int    $regenerationTime Time by which token is renewed, in seconds.
     */
    public function __construct(string $salt, int $expirationTime = 3600, int $regenerationTime = 60)
    {
        $this->tokenDriver = new JsonWebToken($salt);
        $this->expirationTime = $expirationTime;
        $this->regenerationTime = $regenerationTime;
    }

    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param int|string $userID Unique user identifier (usually an int)
     */
    public function save(int|string $userID): void
    {
        $payload = new JsonWebTokenPayload();
        $payload->setApplicationId($userID);
        $payload->setStartTime(time());
        $payload->setEndTime(time()+$this->expirationTime);
        $this->accessToken = $this->tokenDriver->encode($payload);
    }

    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an int) or NULL if none exists.
     */
    public function load(): int|string|null
    {
        if (!$this->accessToken) {
            return null;
        }
        // decode token
        $userID = null;
        try {
            $payload = $this->tokenDriver->decode($this->accessToken, $this->regenerationTime);
            $userID = $payload->getApplicationId();
        } catch (RegenerationException $e) {
            $userID = $e->getPayload()->getApplicationId();
            $this->save($userID);
        } catch (ExpiredException $e) {
            $this->accessToken = null;
        }
        return $userID;
    }

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void
    {
        $this->accessToken = null;
    }
}
