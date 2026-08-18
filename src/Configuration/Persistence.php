<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Persistence\RememberMe as RememberMePersistence;
use Lucinda\WebSecurity\Configuration\Persistence\Session as SessionPersistence;
use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken as SynchronizedTokenPersistence;

/**
 * Encapsulates Persistence logic.
 */
final class Persistence
{
    private array $drivers = [];

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->persistence)) {
            throw new Exception("Tag 'persistence', child of 'security' is required!");
        }
        $subXML = $xml->persistence;

        $this->validate($subXML);
        $this->setDrivers($subXML);
    }

    /**
     * Performs checks if XML obeys the expected architecture
     * 
     * @param \SimpleXMLElement $xml
     * @throws Exception
     * @return void
     */
    private function validate(\SimpleXMLElement $xml): void
    {
        if (isset($xml->synchronizer_token) && (isset($xml->session) || isset($xml->remember_me))) {
            throw new Exception("Synchronizer token persistence is mutually exclusive with session & remember_me!");
        }

        if (isset($xml->remember_me) && !isset($xml->session)) {
            throw new Exception("Remember_me requires session persistence!");
        }
    }

    /**
     * Sets drivers.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDrivers(\SimpleXMLElement $xml): void
    {
        if (isset($xml->session)) {
            $this->drivers[] = new SessionPersistence($xml->session);
        }

        if (isset($xml->remember_me)) {
            $this->drivers[] = new RememberMePersistence($xml->remember_me);
        }

        if (isset($xml->synchronizer_token)) {
            $this->drivers[] = new SynchronizedTokenPersistence($xml->synchronizer_token);
        }
        
        if (empty($this->drivers)) {
            throw new Exception("Tag 'persistence' must have at least one working subtag!");
        }
    }

    /**
     * Gets drivers.
     *
     * @return array
     */
    public function getDrivers(): array
    {
        return $this->drivers;
    }
}
