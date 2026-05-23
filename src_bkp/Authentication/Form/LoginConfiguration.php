<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Encapsulates login request configuration by matching data in xml
 */
class LoginConfiguration extends UrlTargetConfiguration
{
    public const DEFAULT_PARAMETER_USERNAME = "username";
    public const DEFAULT_PARAMETER_PASSWORD = "password";
    public const DEFAULT_PARAMETER_REMEMBER_ME = "remember_me";

    private string $username;
    private string $password;
    private string $rememberMe;

    /**
     * Reads parameter names from XML
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        parent::__construct($xml);
        $this->setUsername($xml);
        $this->setPassword($xml);
        $this->setRememberMe($xml);
    }

    /**
     * Sets value of user name sent in login attempt.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setUsername(\SimpleXMLElement $xml): void
    {
        $this->username = (string) $xml->login["parameter_username"];
        if (!$this->username) {
            $this->username = self::DEFAULT_PARAMETER_USERNAME;
        }
    }

    /**
     * Sets value of user password sent in login attempt.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPassword(\SimpleXMLElement $xml): void
    {
        $this->password = (string) $xml->login["parameter_password"];
        if (!$this->password) {
            $this->password = self::DEFAULT_PARAMETER_PASSWORD;
        }
    }

    /**
     * Sets value of remember me option sent in login attempt (or null, if application doesn't support remember me)
     *
     * @param \SimpleXMLElement $xml
     */
    private function setRememberMe(\SimpleXMLElement $xml): void
    {
        $this->rememberMe = (string) $xml->login["parameter_rememberMe"];
        if (!$this->rememberMe) {
            $this->rememberMe = self::DEFAULT_PARAMETER_REMEMBER_ME;
        }
    }

    /**
     * Gets value of user name sent in login attempt.
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Gets value of user password sent in login attempt.
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Gets value of remember me option sent in login attempt (or null, if application doesn't support remember me)
     *
     * @return string
     */
    public function getRememberMe(): string
    {
        return $this->rememberMe;
    }

    /**
     * Get name of XML sub-tag holding source/target url values
     *
     * @return string
     */
    protected function getTagName(): string
    {
        return "login";
    }
}
