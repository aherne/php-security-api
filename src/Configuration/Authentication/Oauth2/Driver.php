<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

final class Driver
{
    private string $name;
    private string $pageLogin;
    
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setName($xml);
        $this->setPageLogin($xml);
    }

    private function setName(\SimpleXMLElement $xml): void
    {
        if (empty($xml["name"])) {
            throw new ConfigurationException("Attribute 'name' must be set for tag 'driver'");
        }
        $this->name = (string) $xml["name"];
    }

    public function getName(): string
    {
        return $this->name;
    }

    private function setPageLogin(\SimpleXMLElement $xml): void
    {
        if (empty($xml["login"])) {
            throw new ConfigurationException("Attribute 'login' must be set for tag 'oauth2'");
        }
        $this->pageLogin = (string) $xml["login"];
    }

    public function getPageLogin(): ?string
    {
        return $this->pageLogin;
    }
}