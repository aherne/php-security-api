<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Defines blueprints for a driver able to persist user logged in state across requests.
 */
interface PersistenceDriver
{
    /**
     * Loads logged in user's unique identifier from driver.
     *
     * @return int|string|null Unique user identifier (usually an int) or NULL if none exists.
     */
    public function load(): int|string|null;

    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param int|string $userID Unique user identifier (usually an int)
     */
    public function save(int|string $userID): void;

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void;
}
