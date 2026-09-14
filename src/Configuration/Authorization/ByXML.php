<?php

namespace Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\UserRoles;

/**
 * Encapsulates parsing of the security > authorization > by_route XML tag
 */
final class ByXML
{
    private string $callbackLoggedIn;
    private string $callbackLoggedOut;
    private string $rolesDAO;

    /**
     * Sets up object state from the by_route XML tag
     *
     * @param \SimpleXMLElement $xml The by_route XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setRolesDAO($xml);
        $this->setCallbackLoggedIn($xml);
        $this->setCallbackLoggedOut($xml);
    }

    /**
     * Detects DAO\UserRoles class based on 'roles_dao' tag attribute
     *
     * @param \SimpleXMLElement $xml The by_route XML tag
     * @throws ConfigurationException If missing or the class does not implement UserRoles
     */
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

    /**
     * Gets detected DAO\UserRoles class name
     *
     * @return class-string<UserRoles>
     */
    public function getRolesDAO(): string
    {
        return $this->rolesDAO;
    }

    /**
     * Detects authorization failure route for logged-in users based on 'logged_in_callback' tag attribute
     *
     * @param \SimpleXMLElement $xml The by_route XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setCallbackLoggedIn(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_in_callback"])) {
            throw new ConfigurationException("Attribute 'logged_in_callback' must be set for tag 'by_route'");
        }
        $this->callbackLoggedIn = (string) $xml["logged_in_callback"];
    }

    /**
     * Gets authorization failure route for logged-in users
     *
     * @return string
     */
    public function getCallbackLoggedIn(): string
    {
        return $this->callbackLoggedIn;
    }

    /**
     * Detects authorization failure route for guests based on 'logged_out_callback' tag attribute
     *
     * @param \SimpleXMLElement $xml The by_route XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setCallbackLoggedOut(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_out_callback"])) {
            throw new ConfigurationException("Attribute 'logged_out_callback' must be set for tag 'by_route'");
        }
        $this->callbackLoggedOut = (string) $xml["logged_out_callback"];
    }

    /**
     * Gets authorization failure route for guests
     *
     * @return string
     */
    public function getCallbackLoggedOut(): string
    {
        return $this->callbackLoggedOut;
    }
}
