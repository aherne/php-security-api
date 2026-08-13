<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Form;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

/**
 * Encapsulates Login logic.
 */
final class Login
{
    public const DEFAULT_PARAMETER_USERNAME = "username";
    public const DEFAULT_PARAMETER_PASSWORD = "password";
    public const DEFAULT_PARAMETER_REMEMBER_ME = "remember_me";
    public const DEFAULT_PARAMETER_CSRF = "csrf";
    private string $parameterUsername;
    private string $parameterPassword;
    private string $parameterRememberMe;
    private string $parameterCsrf;
    private string $pageSource;
    private string $targetSuccess;
    private string $targetFailure;
    private string $targetThrottled;
    
    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
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
     * Sets page source route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPageSource(\SimpleXMLElement $xml): void
    {
        if (empty($xml["page"])) {
            throw new ConfigurationException("Attribute 'page' must be set for tag 'login'");
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
     * Sets target success route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_success"])) {
            throw new ConfigurationException("Attribute 'target_success' must be set for tag 'login'");
        }
        $this->targetSuccess = (string) $xml["target_success"];
    }

    /**
     * Gets target success route
     *
     * @return string
     */
    public function getTargetSuccess(): string
    {
        return $this->targetSuccess;
    }

    /**
     * Sets target failure route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_failure"])) {
            throw new ConfigurationException("Attribute 'target_failure' must be set for tag 'login'");
        }
        $this->targetFailure = (string) $xml["target_failure"];
    }

    /**
     * Gets target failure route
     *
     * @return string
     */
    public function getTargetFailure(): string
    {
        return $this->targetFailure;
    }

    /**
     * Sets target throttled route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetThrottled(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_throttled"])) {
            throw new ConfigurationException("Attribute 'target_throttled' must be set for tag 'login'");
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
