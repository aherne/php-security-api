<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\Oauth2Login;

/**
 * Encapsulates OAuth2 logic.
 */
final class Oauth2 extends Generic
{
    private string $dao;
    private array $drivers = [];

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setDAO($xml);
        $this->setTargetSuccess($xml);
        $this->setTargetFailure($xml);
        $this->setParameterCsrf($xml);
        $this->setDrivers($xml);
    }

    /**
     * Sets DAO.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'dao' must be set for tag 'oauth2'");
        }
        if (!is_subclass_of($daoClass, Oauth2Login::class)) {
            throw new ConfigurationException("DAO must be instance of ".Oauth2Login::class);
        }
        $this->dao = $daoClass;
    }

    /**
     * Gets DAO.
     *
     * @return string
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Sets drivers.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDrivers(\SimpleXMLElement $xml): void
    {
        foreach ($xml->driver as $child) {
            $this->drivers[] = new Driver($child);
        }
        if (empty($this->drivers)) {
            throw new ConfigurationException("At least one 'driver' child tag must be set for tag 'oauth2'");
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