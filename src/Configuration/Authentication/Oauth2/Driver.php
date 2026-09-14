<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

/**
 * Encapsulates parsing of the security > authentication > oauth2 > driver XML tag
 */
final class Driver
{
    private string $name;
    private string $pageLogin;
    
    /**
     * Sets up object state from the driver XML tag
     *
     * @param \SimpleXMLElement $xml The driver XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setName($xml);
        $this->setPageLogin($xml);
    }

    /**
     * Detects the injected OAuth2 provider name based on 'name' tag attribute
     *
     * @param \SimpleXMLElement $xml The driver XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setName(\SimpleXMLElement $xml): void
    {
        if (empty($xml["name"])) {
            throw new ConfigurationException("Attribute 'name' must be set for tag 'driver'");
        }
        $this->name = (string) $xml["name"];
    }

    /**
     * Gets the name used to select the injected OAuth2 provider
     *
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * Detects the OAuth2 login and callback route based on 'login' tag attribute
     *
     * @param \SimpleXMLElement $xml The driver XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setPageLogin(\SimpleXMLElement $xml): void
    {
        if (empty($xml["login"])) {
            throw new ConfigurationException("Attribute 'login' must be set for tag 'oauth2'");
        }
        $this->pageLogin = (string) $xml["login"];
    }

    /**
     * Gets the OAuth2 login and callback route
     *
     * @return ?string
     */
    public function getPageLogin(): ?string
    {
        return $this->pageLogin;
    }
}