<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\Logout as LogoutDAO;

/**
 * Encapsulates Logout logic.
 */
final class Logout extends Generic
{
    public const DEFAULT_PARAMETER_CSRF = "csrf";
    private string $dao;
    private string $pageSource;
    private string $parameterCsrf;
    
    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
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
     * Sets DAO.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets DAO.
     *
     * @return string
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Sets page source.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPageSource(\SimpleXMLElement $xml): void
    {
        if (empty($xml["page"])) {
            throw new ConfigurationException("Attribute 'page' must be set for tag 'logout'");
        }
        $this->pageSource = (string) $xml["page"];
    }

    /**
     * Gets page source.
     *
     * @return string
     */
    public function getPageSource(): string
    {
        return $this->pageSource;
    }

    /**
     * Sets parameter CSRF.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setParameterCsrf(\SimpleXMLElement $xml): void
    {
        $this->parameterCsrf = !empty($xml["csrf"])?(string) $xml["csrf"]:self::DEFAULT_PARAMETER_CSRF;
    }

    /**
     * Gets parameter CSRF.
     *
     * @return string
     */
    public function getParameterCsrf(): string
    {
        return $this->parameterCsrf;
    }
}
