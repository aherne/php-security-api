<?php

namespace Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\PageAuthorization;
use Lucinda\WebSecurity\DAO\UserAuthorization;

/**
 * Encapsulates parsing of the security > authorization > by_dao XML tag
 */
final class ByDAO
{
    private string $pageDAO;
    private string $userDAO;
    private string $callbackLoggedIn;
    private string $callbackLoggedOut;

    /**
     * Sets up object state from the by_dao XML tag
     *
     * @param \SimpleXMLElement $xml The by_dao XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setPageDAO($xml);
        $this->setUserDAO($xml);
        $this->setCallbackLoggedIn($xml);
        $this->setCallbackLoggedOut($xml);
    }

    /**
     * Detects DAO\PageAuthorization class based on 'page_dao' tag attribute
     *
     * @param \SimpleXMLElement $xml The by_dao XML tag
     * @throws ConfigurationException If missing or the class does not implement PageAuthorization
     */
    private function setPageDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["page_dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'page_dao' must be set for tag 'by_dao'");
        }
        if (!is_subclass_of($daoClass, PageAuthorization::class)) {
            throw new ConfigurationException("DAO must be instance of ".PageAuthorization::class);
        }
        $this->pageDAO = $daoClass;
    }

    /**
     * Gets detected DAO\PageAuthorization class name
     *
     * @return class-string<PageAuthorization>
     */
    public function getPageDAO(): string
    {
        return $this->pageDAO;
    }

    /**
     * Detects DAO\UserAuthorization class based on 'user_dao' tag attribute
     *
     * @param \SimpleXMLElement $xml The by_dao XML tag
     * @throws ConfigurationException If missing or the class does not implement UserAuthorization
     */
    private function setUserDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["user_dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'user_dao' must be set for tag 'by_dao'");
        }
        if (!is_subclass_of($daoClass, UserAuthorization::class)) {
            throw new ConfigurationException("DAO must be instance of ".UserAuthorization::class);
        }
        $this->userDAO = $daoClass;
    }

    /**
     * Gets detected DAO\UserAuthorization class name
     *
     * @return class-string<UserAuthorization>
     */
    public function getUserDAO(): string
    {
        return $this->userDAO;
    }

    /**
     * Detects authorization failure route for logged-in users based on 'logged_in_callback' tag attribute
     *
     * @param \SimpleXMLElement $xml The by_dao XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setCallbackLoggedIn(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_in_callback"])) {
            throw new ConfigurationException("Attribute 'logged_in_callback' must be set for tag 'by_dao'");
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
     * @param \SimpleXMLElement $xml The by_dao XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setCallbackLoggedOut(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_out_callback"])) {
            throw new ConfigurationException("Attribute 'logged_out_callback' must be set for tag 'by_dao'");
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
