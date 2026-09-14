<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Persistence\RememberMe as RememberMePersistence;
use Lucinda\WebSecurity\Configuration\Persistence\Session as SessionPersistence;
use Lucinda\WebSecurity\Configuration\Persistence\SynchronizerToken as SynchronizedTokenPersistence;

/**
 * Encapsulates parsing of the security > persistence XML tag
 */
final class Persistence
{
    /**
     * @var array<SessionPersistence|RememberMePersistence|SynchronizedTokenPersistence>
     */
    private array $drivers = [];

    /**
     * Sets up object state from the security XML tag
     *
     * @param \SimpleXMLElement $xml The security XML tag
     * @throws Exception If a required setting is missing or invalid
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
     * Validates allowed combinations of persistence drivers
     *
     * @param \SimpleXMLElement $xml The persistence XML tag
     * @throws Exception If token and cookie persistence are combined or remember_me lacks session persistence
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
     * Detects persistence configurations from 'session', 'remember_me' and 'synchronizer_token' child tags
     *
     * @param \SimpleXMLElement $xml The persistence XML tag
     * @throws Exception If no driver is configured or a child configuration is invalid
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
     * Gets detected persistence driver configurations in loading order
     *
     * @return array<SessionPersistence|RememberMePersistence|SynchronizedTokenPersistence>
     */
    public function getDrivers(): array
    {
        return $this->drivers;
    }
}
