<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration\Authentication;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\Persistence;
use Lucinda\WebSecurity\Configuration\Authorization;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

final class Configuration
{
    private Persistence $persistence;
    private Csrf $csrf;
    private Authentication $authentication;
    private Authorization $authorization;
    private ?MultiFactorAuthentication $multiFactorAuthentication = null;

    public function __construct(\SimpleXMLElement $xml)
    {
        if (empty($xml->security)) {
            throw new ConfigurationException("Tag 'security' is mandatory!");
        }
        $mainXML = $xml->security;
        $this->persistence = new Persistence($mainXML);
        $this->csrf = new Csrf($mainXML);
        $this->authentication = new Authentication($mainXML);
        $this->authorization = new Authorization($mainXML);
        if (!empty($mainXML->multi_factor_authentication)) {
            $this->multiFactorAuthentication = new MultiFactorAuthentication($mainXML);
        }
    }

    public function getPersistence(): Persistence
    {
        return $this->persistence;
    }

    public function getCsrf(): Csrf
    {
        return $this->csrf;
    }

    public function getAuthentication(): Authentication
    {
        return $this->authentication;
    }

    public function getAuthorization(): Authorization
    {
        return $this->authorization;
    }

    public function getMultiFactorAuthentication(): ?MultiFactorAuthentication
    {
        return $this->multiFactorAuthentication;
    }
}
