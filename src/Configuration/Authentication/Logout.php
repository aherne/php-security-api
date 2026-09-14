<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\Logout as LogoutDAO;

/**
 * Encapsulates parsing of the security > authentication > logout XML tag
 */
final class Logout extends Generic
{
    public const DEFAULT_PARAMETER_CSRF = "csrf";
    private string $dao;
    private string $pageSource;
    private string $parameterCsrf;
    
    /**
     * Sets up object state from the logout XML tag
     *
     * @param \SimpleXMLElement $xml The logout XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setDAO($xml);
        $this->setPageSource($xml);
        $this->setTargetSuccess($xml);
        $this->setTargetFailure($xml);
        $this->setParameterCsrf($xml);
    }

    /**
     * Detects DAO\Logout class based on 'dao' tag attribute
     *
     * @param \SimpleXMLElement $xml The logout XML tag
     * @throws ConfigurationException If missing or the class does not implement LogoutDAO
     */
    private function setDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'dao' must be set for tag 'logout'");
        }
        if (!is_subclass_of($daoClass, LogoutDAO::class)) {
            throw new ConfigurationException("DAO must be instance of ".LogoutDAO::class);
        }
        $this->dao = $daoClass;
    }

    /**
     * Gets detected DAO\Logout class name
     *
     * @return class-string<LogoutDAO>
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Detects logout route based on 'page' tag attribute
     *
     * @param \SimpleXMLElement $xml The logout XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setPageSource(\SimpleXMLElement $xml): void
    {
        if (empty($xml["page"])) {
            throw new ConfigurationException("Attribute 'page' must be set for tag 'logout'");
        }
        $this->pageSource = (string) $xml["page"];
    }

    /**
     * Gets logout route
     *
     * @return string
     */
    public function getPageSource(): string
    {
        return $this->pageSource;
    }

    /**
     * Detects the POST parameter holding the CSRF challenge based on 'csrf' tag attribute
     *
     * Uses DEFAULT_PARAMETER_CSRF when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The logout XML tag
     */
    private function setParameterCsrf(\SimpleXMLElement $xml): void
    {
        $this->parameterCsrf = !empty($xml["csrf"])?(string) $xml["csrf"]:self::DEFAULT_PARAMETER_CSRF;
    }

    /**
     * Gets the POST parameter name holding the CSRF challenge
     *
     * @return string
     */
    public function getParameterCsrf(): string
    {
        return $this->parameterCsrf;
    }
}
