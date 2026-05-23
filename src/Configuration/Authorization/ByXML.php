<?php

namespace Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\UserRoles;

final class ByXML
{
    private string $callbackLoggedIn;
    private string $callbackLoggedOut;
    private string $rolesDAO;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setRolesDAO($xml);
        $this->setCallbackLoggedIn($xml);
        $this->setCallbackLoggedOut($xml);
    }

    private function setRolesDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["roles_dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'roles_dao' must be set for tag 'by_route'");
        }
        if (!is_subclass_of($daoClass, UserRoles::class)) {
            throw new ConfigurationException("DAO must be instance of ".UserRoles::class);
        }
        $this->rolesDAO = $daoClass;
    }

    public function getRolesDAO(): string
    {
        return $this->rolesDAO;
    }

    private function setCallbackLoggedIn(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_in_callback"])) {
            throw new ConfigurationException("Attribute 'logged_in_callback' must be set for tag 'by_route'");
        }
        $this->callbackLoggedIn = (string) $xml["logged_in_callback"];
    }

    public function getCallbackLoggedIn(): string
    {
        return $this->callbackLoggedIn;
    }

    private function setCallbackLoggedOut(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_out_callback"])) {
            throw new ConfigurationException("Attribute 'logged_out_callback' must be set for tag 'by_route'");
        }
        $this->callbackLoggedOut = (string) $xml["logged_out_callback"];
    }

    public function getCallbackLoggedOut(): string
    {
        return $this->callbackLoggedOut;
    }
}
