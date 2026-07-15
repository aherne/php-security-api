<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Authentication\Form;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

/**
 * Encapsulates Authentication logic.
 */
final class Authentication
{
    private array $methods = [];

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

        $this->setMethods($subXML);
    }

    /**
     * Sets methods.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setMethods(\SimpleXMLElement $xml): void
    {
        if (isset($xml->form)) {
            $this->methods[] = new Form($xml->form);
        }
        if (isset($xml->oauth2)) {
            $this->methods[] = new Oauth2($xml->oauth2);
        }
        if (empty($this->methods)) {
            throw new Exception("Tag 'authentication' must have at least a 'form' or an 'oauth2' subtag!");
        }
    }

    /**
     * Gets methods.
     *
     * @return array
     */
    public function getMethods(): array
    {
        return $this->methods;
    }
}
