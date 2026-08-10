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
        if (!isset($xml->persistence)) {
            throw new Exception("Tag 'persistence', child of 'security' is required!");
        }
        $subXML = $xml->persistence;

        $this->setDrivers($subXML);
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

        if (isset($xml->synchronizer_token)) {
            $this->drivers[] = new SynchronizedTokenPersistence($xml->synchronizer_token);
        }

        // remember me can be enabled only if session/synchronizer_token already activated
        if (isset($xml->remember_me) && (isset($xml->session) || isset($xml->synchronizer_token))) {
            $this->drivers[] = new RememberMePersistence($xml->remember_me);
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
