<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\ConfigurationException;

/**
 * Defines an abstract persistence mechanism that works with PersistenceDriver objects.
 */
abstract class PersistenceDriverWrapper
{
    protected PersistenceDriver $driver;

    /**
     * Creates an object.
     *
     * @param  \SimpleXMLElement $xml       Contents of XML tag that sets up persistence driver.
     * @param  string            $ipAddress Client ip address resolved from headers
     * @throws ConfigurationException
     */
    public function __construct(\SimpleXMLElement $xml, string $ipAddress)
    {
        $this->setDriver($xml, $ipAddress);
    }


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
