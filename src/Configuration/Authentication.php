<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Authentication\Form;
use Lucinda\WebSecurity\Configuration\Authentication\Logout;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

/**
 * Encapsulates parsing of the security > authentication XML tag
 */
final class Authentication
{
    /**
     * @var array<Form|Oauth2>
     */
    private array $loginMethods = [];
    private Logout $logoutMethod;

    /**
     * Sets up object state from the security XML tag
     *
     * @param \SimpleXMLElement $xml The security XML tag
     * @throws Exception If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->authentication)) {
            throw new Exception("Tag 'authentication', child of 'security' is required!");
        }
        $subXML = $xml->authentication;

        $this->setLoginMethods($subXML);
        $this->setLogoutMethod($subXML);
    }

    /**
     * Detects login method configurations from 'form' and 'oauth2' child tags
     *
     * @param \SimpleXMLElement $xml The authentication XML tag
     * @throws Exception If no login method is configured or a child configuration is invalid
     */
    private function setLoginMethods(\SimpleXMLElement $xml): void
    {
        if (isset($xml->form)) {
            $this->loginMethods[] = new Form($xml->form);
        }
        if (isset($xml->oauth2)) {
            $this->loginMethods[] = new Oauth2($xml->oauth2);
        }
        if (empty($this->loginMethods)) {
            throw new Exception("Tag 'authentication' must have at least a 'form' or an 'oauth2' subtag!");
        }
    }

    /**
     * Detects logout configuration from the required 'logout' child tag
     *
     * @param \SimpleXMLElement $xml The authentication XML tag
     * @throws Exception If the child tag is missing or its configuration is invalid
     */
    private function setLogoutMethod(\SimpleXMLElement $xml): void
    {
        if (!isset($xml->logout)) {
            throw new Exception("Tag 'authentication' must have a 'logout' subtag!");
        }
        $this->logoutMethod = new Logout($xml->logout);
    }

    /**
     * Gets detected login method configurations
     *
     * @return array<Form|Oauth2>
     */
    public function getLoginMethods(): array
    {
        return $this->loginMethods;
    }

    /**
     * Gets detected logout configuration
     *
     * @return Logout
     */
    public function getLogoutMethod(): Logout
    {
        return $this->logoutMethod;
    }
}
