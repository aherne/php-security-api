<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken as Configuration;
use Lucinda\WebSecurity\PersistenceDrivers\Wrapper as AbstractWrapper;

/**
 * Binds SynchronizerTokenPersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and
 * sets up an object on which one can forward synchronizer token operations.
 */
final class Wrapper extends AbstractWrapper
{
    public function __construct(Configuration $configuration, string $ipAddress)
    {
        $this->setDriver($configuration, $ipAddress);
    }

    /**
     * Sets up current persistence driver from configuration into driver property.
     *
     * @param  Configuration $configuration Persistence driver configuration
     * @param  string        $ipAddress     Detected client IP address
     */
    protected function setDriver(Configuration $configuration, string $ipAddress): void
    {
        $this->driver = new PersistenceDriver(
            $configuration->getSecret(),
            $ipAddress,
            $configuration->getExpirationTime(),
            $configuration->getRegenerationTime()
        );
    }
}
