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
     * @return mixed Unique user identifier (usually an integer) or NULL if none exists.
     */
    public function load();
    
    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param mixed $userID Unique user identifier (usually an integer)
     */
    public function save($userID): void;
    
    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void;
}
