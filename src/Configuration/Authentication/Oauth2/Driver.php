<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

/**
 * Encapsulates Driver logic.
 */
final class Driver
{
    private string $name;
    private string $pageLogin;
    
    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setName($xml);
        $this->setPageLogin($xml);
    }

    /**
     * Sets name.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setName(\SimpleXMLElement $xml): void
    {
        if (empty($xml["name"])) {
            throw new ConfigurationException("Attribute 'name' must be set for tag 'driver'");
        }
        $this->name = (string) $xml["name"];
    }

    /**
     * Gets name.
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Sets page login.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPageLogin(\SimpleXMLElement $xml): void
    {
        if (empty($xml["login"])) {
            throw new ConfigurationException("Attribute 'login' must be set for tag 'oauth2'");
        }
        $this->pageLogin = (string) $xml["login"];
    }

    /**
     * Gets page login.
     *
     * @return ?string
     */
    public function getPageLogin(): ?string
    {
        return $this->pageLogin;
    }
}