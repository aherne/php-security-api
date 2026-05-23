<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

use Lucinda\WebSecurity\PersistenceDrivers\Token\SynchronizerTokenPersistenceDriver;
use Lucinda\WebSecurity\ConfigurationException;

/**
 * Binds SynchronizerTokenPersistenceDriver @ SECURITY API with settings from configuration.xml @ SERVLETS-API and
 * sets up an object on which one can forward synchronizer token operations.
 */
class SynchronizerTokenWrapper extends PersistenceDriverWrapper
{
    public const DEFAULT_EXPIRATION_TIME = 3600;
    public const DEFAULT_REGENERATION_TIME = 60;

    /**
     * Sets up current persistence driver from XML into driver property.
     *
     * @param  \SimpleXMLElement $xml       Contents of XML tag that sets up persistence driver.
     * @param  string            $ipAddress Detected client IP address
     * @throws ConfigurationException If resources referenced in XML do not exist or do not extend/implement blueprint.
     */
    protected function setDriver(\SimpleXMLElement $xml, string $ipAddress): void
    {
        $secret = (string) $xml["secret"];
        if (!$secret) {
            throw new ConfigurationException("Attribute 'secret' is mandatory for 'synchronizer_token' tag");
        }

        $expirationTime = (int) $xml["expiration"];
        if (!$expirationTime) {
            $expirationTime = self::DEFAULT_EXPIRATION_TIME;
        }

        $regenerationTime = (int) $xml["regeneration"];
        if (!$regenerationTime) {
            $regenerationTime = self::DEFAULT_REGENERATION_TIME;
        }

        $this->driver = new SynchronizerTokenPersistenceDriver(
            $secret,
            $ipAddress,
            $expirationTime,
            $regenerationTime
        );
    }
}
