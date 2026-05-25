<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration\Authentication;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\Persistence;
use Lucinda\WebSecurity\Configuration\Authorization;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

/**
 * Encapsulates web security configuration.
 */
final class Configuration
{
    private Persistence $persistence;
    private Csrf $csrf;
    private Authentication $authentication;
    private Authorization $authorization;
    private ?MultiFactorAuthentication $multiFactorAuthentication = null;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
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

    /**
     * Gets persistence.
     *
     * @return Persistence
     */
    public function getPersistence(): Persistence
    {
        return $this->persistence;
    }

    /**
     * Gets CSRF.
     *
     * @return Csrf
     */
    public function getCsrf(): Csrf
    {
        return $this->csrf;
    }

    /**
     * Gets authentication.
     *
     * @return Authentication
     */
    public function getAuthentication(): Authentication
    {
        return $this->authentication;
    }

    /**
     * Gets authorization.
     *
     * @return Authorization
     */
    public function getAuthorization(): Authorization
    {
        return $this->authorization;
    }

    /**
     * Gets multi-factor authentication.
     *
     * @return ?MultiFactorAuthentication
     */
    public function getMultiFactorAuthentication(): ?MultiFactorAuthentication
    {
        return $this->multiFactorAuthentication;
    }
}
