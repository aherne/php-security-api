<?php

namespace Lucinda\WebSecurity\Detectors;

use Lucinda\WebSecurity\Configuration\Persistence;
use Lucinda\WebSecurity\Configuration\Persistence\RememberMe;
use Lucinda\WebSecurity\Configuration\Persistence\Session;
use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken;
use Lucinda\WebSecurity\PersistenceDrivers\Session\Wrapper as SessionWrapper;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMe\Wrapper as RememberMeWrapper;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\Wrapper as SynchronizerTokenWrapper;
use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;

/**
 * Detects mechanisms for authenticated state persistence set in security.persistence XML tag.
 */
final class PersistenceDrivers
{
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers = [];

    /**
     * Performs detection process
     *
     * @param  Persistence $configuration
     * @param  string            $ipAddress
     */
    public function __construct(Persistence $configuration, string $ipAddress)
    {
        $this->setPersistenceDrivers($configuration, $ipAddress);
    }

    /**
     * Reads persistence configuration and collects matching persistence drivers.
     *
     * @param  Persistence $configuration
     * @param  string            $ipAddress
     */
    private function setPersistenceDrivers(Persistence $configuration, string $ipAddress): void
    {
        foreach ($configuration->getDrivers() as $driverConfiguration) {
            $wrapper = match (true) {
                $driverConfiguration instanceof Session => new SessionWrapper($driverConfiguration, $ipAddress),
                $driverConfiguration instanceof RememberMe => new RememberMeWrapper($driverConfiguration, $ipAddress),
                $driverConfiguration instanceof SynchronizerToken => new SynchronizerTokenWrapper($driverConfiguration, $ipAddress)
            };
            $this->persistenceDrivers[] = $wrapper->getDriver();
        }
    }

    /**
     * Gets detected drivers for authenticated state persistence.
     *
     * @return PersistenceDriver[]
     */
    public function getPersistenceDrivers(): array
    {
        return $this->persistenceDrivers;
    }
}
