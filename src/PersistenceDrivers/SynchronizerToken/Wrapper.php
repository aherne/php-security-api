<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken;

use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken as Configuration;
use Lucinda\WebSecurity\PersistenceDrivers\Wrapper as AbstractWrapper;

/**
 * Constructs a synchronizer-token persistence driver from its matching configuration
 *
 * Passes the configured encryption secret, token lifetime, renewal interval,
 * and client IP to the driver. The constructed driver is available through
 * getDriver(); this wrapper does not read request headers or emit a token.
 *
 * @see \Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken
 * @see PersistenceDriver
 */
final class Wrapper extends AbstractWrapper
{
    /**
     * Creates the configured synchronizer-token persistence driver
     *
     * @param Configuration $configuration Parsed persistence settings
     * @param string $ipAddress Client IP for binding, or an empty string when IP binding is disabled
     */
    public function __construct(Configuration $configuration, string $ipAddress)
    {
        $this->setDriver($configuration, $ipAddress);
    }

    /**
     * Builds the synchronizer-token driver from configuration values
     *
     * @param Configuration $configuration Parsed persistence settings
     * @param string $ipAddress Client IP for binding, or an empty string when IP binding is disabled
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
