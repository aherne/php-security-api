<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\SessionWrapper;
use Lucinda\WebSecurity\PersistenceDrivers\RememberMeWrapper;
use Lucinda\WebSecurity\PersistenceDrivers\SynchronizerTokenWrapper;
use Lucinda\WebSecurity\PersistenceDrivers\JsonWebTokenWrapper;

/**
 * Detects mechanisms for authenticated state persistence set in security.persistence XML tag.
 */
class PersistenceDriversDetector
{
    /**
     * @var PersistenceDriver[]
     */
    private array $persistenceDrivers;

    /**
     * Performs detection process
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $ipAddress
     * @throws ConfigurationException
     */
    public function __construct(\SimpleXMLElement $xml, string $ipAddress)
    {
        $this->setPersistenceDrivers($xml, $ipAddress);
    }

    /**
     * Reads &lt;persistence&gt; tag and collects matching persistence drivers
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $ipAddress
     * @throws ConfigurationException
     */
    private function setPersistenceDrivers(\SimpleXMLElement $xml, string $ipAddress): void
    {
        $xml = $xml->persistence;
        if (empty($xml)) {
            return;
        } // it is allowed for elements to not persist

        if ($xml->session) {
            $wrapper = new SessionWrapper($xml->session, $ipAddress);
            $this->persistenceDrivers[] = $wrapper->getDriver();
        }

        if ($xml->remember_me) {
            $wrapper = new RememberMeWrapper($xml->remember_me, $ipAddress);
            $this->persistenceDrivers[] = $wrapper->getDriver();
        }

        if ($xml->synchronizer_token) {
            $wrapper = new SynchronizerTokenWrapper($xml->synchronizer_token, $ipAddress);
            $this->persistenceDrivers[] = $wrapper->getDriver();
        }

        if ($xml->json_web_token) {
            $wrapper = new JsonWebTokenWrapper($xml->json_web_token, $ipAddress);
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
