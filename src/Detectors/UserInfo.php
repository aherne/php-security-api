<?php

namespace Lucinda\WebSecurity\Detectors;

use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver as TokenPersistenceDriver;

/**
 * Detects logged in unique user identifier from persistence drivers.
 */
final class UserInfo
{
    private ?LoggedInUserInfo $userInfo;

    /**
     * Sets logged in user id based on persistence drivers
     *
     * @param PersistenceDriver[] $persistenceDrivers List of persistence drivers to detect from.
     * @param string              $accessToken
     */
    public function __construct(array $persistenceDrivers, string $accessToken="")
    {
        $this->setUserInfo($persistenceDrivers, $accessToken);
    }

    /**
     * Saves detected logged in user info from persistence drivers.
     *
     * @param PersistenceDriver[] $persistenceDrivers List of persistence drivers to detect from.
     */
    private function setUserInfo(array $persistenceDrivers, string $accessToken): void
    {
        foreach ($persistenceDrivers as $persistenceDriver) {
            if ($accessToken && $persistenceDriver instanceof TokenPersistenceDriver) {
                $persistenceDriver->setAccessToken($accessToken);
            }
            $this->userInfo = $persistenceDriver->load();
            if ($this->userInfo !== null) {
                return; // already found (no point moving forward)
            }
        }
    }

    /**
     * Gets detected logged in user info
     *
     * @return ?LoggedInUserInfo
     */
    public function getUserInfo(): ?LoggedInUserInfo
    {
        return $this->userInfo;
    }
}
