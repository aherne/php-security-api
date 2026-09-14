<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Provides access to a persistence driver built from its matching configuration
 *
 * Concrete wrappers translate configuration objects into driver constructor
 * arguments. Persistence operations are performed on the exposed driver.
 *
 * @see PersistenceDriver
 */
abstract class Wrapper
{
    protected PersistenceDriver $driver;

    /**
     * Gets the configured persistence driver
     *
     * @return PersistenceDriver Constructed driver on which persistence operations can be performed
     */
    public function getDriver(): PersistenceDriver
    {
        return $this->driver;
    }
}
