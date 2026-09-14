<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

use Lucinda\WebSecurity\Configuration\Persistence\Session as Configuration;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSecurityOptions;
use Lucinda\WebSecurity\PersistenceDrivers\Wrapper as AbstractWrapper;

/**
 * Constructs a session persistence driver from its matching configuration
 *
 * Maps configuration values to cookie security options and installs the
 * configured session save handler, when provided. The constructed driver
 * is available through getDriver().
 *
 * @see \Lucinda\WebSecurity\Configuration\Persistence\Session
 * @see PersistenceDriver
 */
final class Wrapper extends AbstractWrapper
{
    /**
     * Creates the configured session persistence driver
     *
     * @param Configuration $configuration Parsed persistence settings
     * @param string $ipAddress Client IP for binding, or an empty string when IP binding is disabled
     * @throws \Throwable If the configured session handler throws during initialization
     */
    public function __construct(Configuration $configuration, string $ipAddress)
    {
        $this->setDriver($configuration, $ipAddress);
    }

    /**
     * Builds the session driver and installs the configured session save handler
     *
     * @param Configuration $configuration Parsed persistence settings
     * @param string $ipAddress Client IP for binding, or an empty string when IP binding is disabled
     * @throws \Throwable If the configured session handler throws during initialization
     */
    protected function setDriver(Configuration $configuration, string $ipAddress): void
    {
        $securityOptions = new CookieSecurityOptions();
        $securityOptions->setExpirationTime($configuration->getExpirationTime() ?? 0);
        $securityOptions->setIsHttpOnly($configuration->getIsHttpOnly() ?? false);
        $securityOptions->setIsSecure($configuration->getIsHttpsOnly() ?? false);
        if ($sameSite = $configuration->getSameSite()) {
            $securityOptions->setSameSite($sameSite);
        }

        if ($handler = $configuration->getHandler()) {
            session_set_save_handler(new $handler(), true);
        }

        $this->driver = new PersistenceDriver(
            $configuration->getParameterName(),
            $securityOptions,
            $ipAddress
        );
    }
}
