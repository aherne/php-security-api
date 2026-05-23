<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Defines an abstract persistence mechanism that works with PersistenceDriver objects.
 */
abstract class Wrapper
{
    protected PersistenceDriver $driver;

    /**
     * Gets current persistence driver.
     *
     * @return PersistenceDriver
     */
    public function getDriver(): PersistenceDriver
    {
        return $this->driver;
    }
}
