<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\Token\PersistenceDriver as TokenPersistenceDriver;

/**
 * Detects logged in unique user identifier from persistence drivers.
 */
class UserIdDetector
{
    private int|string|null $userID;

    /**
     * Sets logged in user id based on persistence drivers
     *
     * @param PersistenceDriver[] $persistenceDrivers List of persistence drivers to detect from.
     * @param string              $accessToken
     */
    public function __construct(array $persistenceDrivers, string $accessToken="")
    {
        $this->setUserID($persistenceDrivers, $accessToken);
    }

    /**
     * Saves detected unique user identifier from persistence drivers.
     *
     * @param PersistenceDriver[] $persistenceDrivers List of persistence drivers to detect from.
     */
    private function setUserID(array $persistenceDrivers, string $accessToken): void
    {
        foreach ($persistenceDrivers as $persistenceDriver) {
            if ($accessToken && $persistenceDriver instanceof TokenPersistenceDriver) {
                $persistenceDriver->setAccessToken($accessToken);
            }
            $this->userID = $persistenceDriver->load();
            if ($this->userID) {
                break;
            }
        }
    }

    /**
     * Gets detected unique user identifier
     *
     * @return int|string|null
     */
    public function getUserID(): int|string|null
    {
        return $this->userID;
    }
}
