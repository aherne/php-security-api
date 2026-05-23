<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Form\Login;
use Lucinda\WebSecurity\Configuration\Authentication\Form\Logout;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\FormAuthentication;

final class Form
{
    private string $dao;
    private Login $loginPolicy;
    private Logout $logoutPolicy;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setDAO($xml);
        $this->setLoginPolicy($xml);
        $this->setLogoutPolicy($xml);
    }

    private function setDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'dao' must be set for tag 'form'");
        }
        if (!is_subclass_of($daoClass, FormAuthentication::class)) {
            throw new ConfigurationException("DAO must be instance of ".FormAuthentication::class);
        }
        $this->dao = $daoClass;
    }

    public function getDAO(): string
    {
        return $this->dao;
    }

    private function setLoginPolicy(\SimpleXMLElement $xml): void
    {
        if (empty($xml->login)) {
            throw new ConfigurationException("Child tag 'login' must be set for tag 'form'");
        }
        $this->loginPolicy = new Login($xml->login);
    }

    public function getLoginPolicy(): Login
    {
        return $this->loginPolicy;
    }

    private function setLogoutPolicy(\SimpleXMLElement $xml): void
    {
        if (empty($xml->logout)) {
            throw new ConfigurationException("Child tag 'logout' must be set for tag 'form'");
        }
        $this->logoutPolicy = new Logout($xml->logout);
    }

    public function getLogoutPolicy(): Logout
    {
        return $this->logoutPolicy;
    }
}