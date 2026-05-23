<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\Authentication\Form;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

final class Authentication
{
    private array $methods = [];

    public function __construct(\SimpleXMLElement $xml)
    {
        $subXML = $xml->authentication;
        if (empty($subXML)) {
            throw new Exception("Tag 'authentication', child of 'security' is required!");
        }

        $this->setMethods($subXML);
    }

    private function setMethods(\SimpleXMLElement $xml): void
    {
        if (!empty($xml->form)) {
            $this->methods[] = new Form($xml->form);
        }
        if (!empty($xml->oauth2)) {
            $this->methods[] = new Oauth2($xml->oauth2);
        }
        if (empty($this->methods)) {
            throw new Exception("Tag 'authentication' must have at least a 'form' or an 'oauth2' subtag!");
        }
    }

    public function getMethods(): array
    {
        return $this->methods;
    }
}
