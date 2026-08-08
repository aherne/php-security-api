<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Form\Login;
use Lucinda\WebSecurity\Configuration\Authentication\Form\Logout;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\FormAuthentication;
use Lucinda\WebSecurity\DAO\Throttler\FormLogin as FormLoginThrottler;

/**
 * Encapsulates Form logic.
 */
final class Form
{
    private string $dao;
    private string $throttler;
    private Login $loginPolicy;
    private Logout $logoutPolicy;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setDAO($xml);
        $this->setThrottler($xml);
        $this->setLoginPolicy($xml);
        $this->setLogoutPolicy($xml);
    }

    /**
     * Sets DAO.
     *
     * @param \SimpleXMLElement $xml
     */
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

    /**
     * Gets DAO.
     *
     * @return string
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Sets throttler DAO.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setThrottler(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["throttler"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'throttler' must be set for tag 'form'");
        }
        if (!is_subclass_of($daoClass, FormLoginThrottler::class)) {
            throw new ConfigurationException("Throttler DAO must be instance of ".FormLoginThrottler::class);
        }
        $this->throttler = $daoClass;
    }

    /**
     * Gets throttler DAO.
     *
     * @return string
     */
    public function getThrottler(): string
    {
        return $this->throttler;
    }

    /**
     * Sets login policy.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setLoginPolicy(\SimpleXMLElement $xml): void
    {
        if (!isset($xml->login)) {
            throw new ConfigurationException("Child tag 'login' must be set for tag 'form'");
        }
        $this->loginPolicy = new Login($xml->login);
    }

    /**
     * Gets login policy.
     *
     * @return Login
     */
    public function getLoginPolicy(): Login
    {
        return $this->loginPolicy;
    }

    /**
     * Sets logout policy.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setLogoutPolicy(\SimpleXMLElement $xml): void
    {
        if (!isset($xml->logout)) {
            throw new ConfigurationException("Child tag 'logout' must be set for tag 'form'");
        }
        $this->logoutPolicy = new Logout($xml->logout);
    }

    /**
     * Gets logout policy.
     *
     * @return Logout
     */
    public function getLogoutPolicy(): Logout
    {
        return $this->logoutPolicy;
    }
}
