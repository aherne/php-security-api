<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\FormLogin;
use Lucinda\WebSecurity\DAO\Throttler\FormLogin as FormLoginThrottler;

/**
 * Encapsulates parsing of the security > authentication > form XML tag
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
     * Sets up object state from the form XML tag
     *
     * @param \SimpleXMLElement $xml The form XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
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
     * Detects DAO\FormLogin class based on 'dao' tag attribute
     *
     * @param \SimpleXMLElement $xml The form XML tag
     * @throws ConfigurationException If missing or the class does not implement FormLogin
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
     * Gets detected DAO\FormLogin class name
     *
     * @return class-string<FormLogin>
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Detects DAO\Throttler\FormLogin class based on 'throttler' tag attribute
     *
     * @param \SimpleXMLElement $xml The form XML tag
     * @throws ConfigurationException If missing or the class does not implement FormLoginThrottler
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
     * Gets detected DAO\Throttler\FormLogin class name
     *
     * @return class-string<FormLoginThrottler>
     */
    public function getThrottler(): string
    {
        return $this->throttler;
    }

    /**
     * Detects page source route based on 'page' tag attribute
     *
     * @param \SimpleXMLElement $xml The form XML tag
     * @throws ConfigurationException If the attribute is missing or empty
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
     * Detects target throttled route based on 'target_throttled' tag attribute
     *
     * @param \SimpleXMLElement $xml The form XML tag
     * @throws ConfigurationException If the attribute is missing or empty
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
     * Detects the POST parameter holding the username based on 'parameter_username' tag attribute
     *
     * Uses DEFAULT_PARAMETER_USERNAME when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The form XML tag
     */
    private function setParameterUsername(\SimpleXMLElement $xml): void
    {
        $this->parameterUsername = !empty($xml["parameter_username"])?(string) $xml["parameter_username"]:self::DEFAULT_PARAMETER_USERNAME;
    }

    /**
     * Gets the POST parameter name holding the username
     *
     * @return string
     */
    public function getParameterUsername(): string
    {
        return $this->parameterUsername;
    }

    /**
     * Detects the POST parameter holding the password based on 'parameter_password' tag attribute
     *
     * Uses DEFAULT_PARAMETER_PASSWORD when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The form XML tag
     */
    private function setParameterPassword(\SimpleXMLElement $xml): void
    {
        $this->parameterPassword = !empty($xml["parameter_password"])?(string) $xml["parameter_password"]:self::DEFAULT_PARAMETER_PASSWORD;
    }

    /**
     * Gets the POST parameter name holding the password
     *
     * @return string
     */
    public function getParameterPassword(): string
    {
        return $this->parameterPassword;
    }

    /**
     * Detects the POST parameter holding the remember-me flag based on 'parameter_remember_me' tag attribute
     *
     * Uses DEFAULT_PARAMETER_REMEMBER_ME when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The form XML tag
     */
    private function setParameterRememberMe(\SimpleXMLElement $xml): void
    {
        $this->parameterRememberMe = !empty($xml["parameter_remember_me"])?(string) $xml["parameter_remember_me"]:self::DEFAULT_PARAMETER_REMEMBER_ME;
    }

    /**
     * Gets the POST parameter name holding the remember-me flag
     *
     * @return string
     */
    public function getParameterRememberMe(): string
    {
        return $this->parameterRememberMe;
    }

    /**
     * Detects the POST parameter holding the CSRF challenge based on 'csrf' tag attribute
     *
     * Uses DEFAULT_PARAMETER_CSRF when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The form XML tag
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
