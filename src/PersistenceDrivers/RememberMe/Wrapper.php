<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\Configuration\Persistence\RememberMe as Configuration;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\Wrapper as AbstractWrapper;

/**
 * Binds RememberMePersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and
 * sets up an object on which one can forward remember-me cookie operations.
 */
final class Wrapper extends AbstractWrapper
{
    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param string $ipAddress
     */
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
        $securityOptions = new CookieSecurityOptions();
        $securityOptions->setExpirationTime($configuration->getExpirationTime());
        $securityOptions->setIsHttpOnly($configuration->getIsHttpOnly() ?? false);
        $securityOptions->setIsSecure($configuration->getIsHttpsOnly() ?? false);
        if ($sameSite = $configuration->getSameSite()) {
            $securityOptions->setSameSite(CookieSameSiteOptions::from($sameSite));
        }

        $this->driver = new PersistenceDriver(
            $configuration->getSecret(),
            $configuration->getParameterName(),
            $securityOptions,
            $ipAddress
        );
    }
}
