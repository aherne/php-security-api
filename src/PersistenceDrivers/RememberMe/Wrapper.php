<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\RememberMe;

use Lucinda\WebSecurity\Configuration\Persistence\RememberMe as Configuration;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\Wrapper as AbstractWrapper;

/**
 * Constructs a remember-me persistence driver from its matching configuration
 *
 * Maps the configured encryption secret, cookie name, lifetime, security
 * attributes, and client IP to the driver. The constructed driver is
 * available through getDriver(); construction does not issue a cookie.
 *
 * @see \Lucinda\WebSecurity\Configuration\Persistence\RememberMe
 * @see PersistenceDriver
 */
final class Wrapper extends AbstractWrapper
{
    /**
     * Creates the configured remember-me persistence driver
     *
     * @param Configuration $configuration Parsed persistence settings
     * @param string $ipAddress Client IP for binding, or an empty string when IP binding is disabled
     */
    public function __construct(Configuration $configuration, string $ipAddress)
    {
        $this->setDriver($configuration, $ipAddress);
    }

    /**
     * Builds the remember-me driver from configuration values
     *
     * @param Configuration $configuration Parsed persistence settings
     * @param string $ipAddress Client IP for binding, or an empty string when IP binding is disabled
     */
    protected function setDriver(Configuration $configuration, string $ipAddress): void
    {
        $securityOptions = new CookieSecurityOptions();
        $securityOptions->setExpirationTime($configuration->getExpirationTime());
        $securityOptions->setIsHttpOnly($configuration->getIsHttpOnly() ?? false);
        $securityOptions->setIsSecure($configuration->getIsHttpsOnly() ?? false);
        if ($sameSite = $configuration->getSameSite()) {
            $securityOptions->setSameSite($sameSite);
        }

        $this->driver = new PersistenceDriver(
            $configuration->getSecret(),
            $configuration->getParameterName(),
            $securityOptions,
            $ipAddress
        );
    }
}
