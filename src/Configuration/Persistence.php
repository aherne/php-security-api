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
    private array $drivers;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $subXML = $xml->persistence;
        if (empty($subXML)) {
            throw new Exception("Tag 'persistence', child of 'security' is required!");
        }

        $this->setDrivers($subXML);
    }

    /**
     * Sets drivers.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDrivers(\SimpleXMLElement $xml): void
    {
        if (!empty($xml->session)) {
            $this->drivers[] = new SessionPersistence($xml->session);
        }

        if (!empty($xml->remember_me)) {
            $this->drivers[] = new RememberMePersistence($xml->remember_me);
        }

        if (!empty($xml->synchronizer_token)) {
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
