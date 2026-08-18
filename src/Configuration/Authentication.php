<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Authentication\Form;
use Lucinda\WebSecurity\Configuration\Authentication\Logout;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

/**
 * Encapsulates Authentication logic.
 */
final class Authentication
{
    private array $loginMethods = [];
    private Logout $logoutMethod;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
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
     * Sets login methods.
     *
     * @param \SimpleXMLElement $xml
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
     * Sets logout method.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setLogoutMethod(\SimpleXMLElement $xml): void
    {
        if (!isset($xml->logout)) {
            throw new Exception("Tag 'authentication' must have a 'logout' subtag!");
        }
        $this->logoutMethod = new Logout($xml->logout);
    }

    /**
     * Gets login methods configuration
     *
     * @return array
     */
    public function getLoginMethods(): array
    {
        return $this->loginMethods;
    }

    /**
     * Gets logout method configuration
     * 
     * @return Logout
     */
    public function getLogoutMethod(): Logout
    {
        return $this->logoutMethod;
    }
}
