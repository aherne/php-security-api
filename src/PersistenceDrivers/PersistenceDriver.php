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
     * @return LoggedInUserInfo|null Encapsulated persistent authentication
     */
    public function load(): ?LoggedInUserInfo;

    /**
     * Saves user's unique identifier into driver (eg: on login).
     *
     * @param LoggedInUserInfo $authentication Encapsulated persistent authentication
     */
    public function save(LoggedInUserInfo $authentication): void;

    /**
     * Removes user's unique identifier from driver (eg: on logout).
     */
    public function clear(): void;
}
