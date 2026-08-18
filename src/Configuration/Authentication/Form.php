<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\FormLogin;
use Lucinda\WebSecurity\DAO\Throttler\FormLogin as FormLoginThrottler;

/**
 * Encapsulates Form logic.
 */
final class Form extends Generic
{
    public const DEFAULT_PARAMETER_USERNAME = "username";
    public const DEFAULT_PARAMETER_PASSWORD = "password";
    public const DEFAULT_PARAMETER_REMEMBER_ME = "remember_me";
    public const DEFAULT_PARAMETER_CSRF = "csrf";
    private string $dao;
    private string $throttler;
    private string $parameterUsername;
    private string $parameterPassword;
    private string $parameterRememberMe;
    private string $pageSource;
    private string $targetThrottled;
    private string $parameterCsrf;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setDAO($xml);
        $this->setThrottler($xml);
        $this->setPageSource($xml);
        $this->setTargetSuccess($xml);
        $this->setTargetFailure($xml);
        $this->setTargetThrottled($xml);
        $this->setParameterUsername($xml);
        $this->setParameterPassword($xml);
        $this->setParameterRememberMe($xml);
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
            throw new ConfigurationException("Attribute 'dao' must be set for tag 'form'");
        }
        if (!is_subclass_of($daoClass, FormLogin::class)) {
            throw new ConfigurationException("DAO must be instance of ".FormLogin::class);
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
     * Sets page source route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPageSource(\SimpleXMLElement $xml): void
    {
        if (empty($xml["page"])) {
            throw new ConfigurationException("Attribute 'page' must be set for tag 'form'");
        }
        $this->pageSource = (string) $xml["page"];
    }

    /**
     * Gets page source route
     *
     * @return string
     */
    public function getPageSource(): string
    {
        return $this->pageSource;
    }

    /**
     * Sets target throttled route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetThrottled(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_throttled"])) {
            throw new ConfigurationException("Attribute 'target_throttled' must be set for tag 'form'");
        }
        $this->targetThrottled = (string) $xml["target_throttled"];
    }

    /**
     * Gets target throttled route
     *
     * @return string
     */
    public function getTargetThrottled(): string
    {
        return $this->targetThrottled;
    }

    /**
     * Sets parameter username.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setParameterUsername(\SimpleXMLElement $xml): void
    {
        $this->parameterUsername = !empty($xml["parameter_username"])?(string) $xml["parameter_username"]:self::DEFAULT_PARAMETER_USERNAME;
    }

    /**
     * Gets parameter username.
     *
     * @return string
     */
    public function getParameterUsername(): string
    {
        return $this->parameterUsername;
    }

    /**
     * Sets parameter password.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setParameterPassword(\SimpleXMLElement $xml): void
    {
        $this->parameterPassword = !empty($xml["parameter_password"])?(string) $xml["parameter_password"]:self::DEFAULT_PARAMETER_PASSWORD;
    }

    /**
     * Gets parameter password.
     *
     * @return string
     */
    public function getParameterPassword(): string
    {
        return $this->parameterPassword;
    }

    /**
     * Sets parameter remember me.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setParameterRememberMe(\SimpleXMLElement $xml): void
    {
        $this->parameterRememberMe = !empty($xml["parameter_remember_me"])?(string) $xml["parameter_remember_me"]:self::DEFAULT_PARAMETER_REMEMBER_ME;
    }

    /**
     * Gets parameter remember me.
     *
     * @return string
     */
    public function getParameterRememberMe(): string
    {
        return $this->parameterRememberMe;
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
