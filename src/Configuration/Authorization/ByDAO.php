<?php

namespace Lucinda\WebSecurity\Configuration\Authorization;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\PageAuthorization;
use Lucinda\WebSecurity\DAO\UserAuthorization;

final class ByDAO
{
    private string $pageDAO;
    private string $userDAO;
    private string $callbackLoggedIn;
    private string $callbackLoggedOut;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setPageDAO($xml);
        $this->setUserDAO($xml);
        $this->setCallbackLoggedIn($xml);
        $this->setCallbackLoggedOut($xml);
    }

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

    public function getPageDAO(): string
    {
        return $this->pageDAO;
    }

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

    public function getUserDAO(): string
    {
        return $this->userDAO;
    }

    private function setCallbackLoggedIn(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logged_in_callback"])) {
            throw new ConfigurationException("Attribute 'logged_in_callback' must be set for tag 'by_dao'");
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
            throw new ConfigurationException("Attribute 'logged_out_callback' must be set for tag 'by_dao'");
        }
        $this->callbackLoggedOut = (string) $xml["logged_out_callback"];
    }

    public function getCallbackLoggedOut(): string
    {
        return $this->callbackLoggedOut;
    }
}
