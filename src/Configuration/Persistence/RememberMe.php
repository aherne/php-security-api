<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\FieldValidator;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;

/**
 * Encapsulates parsing of the security > persistence > remember_me XML tag
 */
final class RememberMe extends AbstractPersistence
{
    public const DEFAULT_PARAMETER_NAME = "uid";
    public const DEFAULT_EXPIRATION_TIME = 24*3600;
    private string $parameterName;
    private string $secret;
    private ?bool $isHttpOnly = null;
    private ?bool $isHttpsOnly = null;
    private ?CookieSameSiteOptions $sameSite = null;

    /**
     * Sets up object state from the remember_me XML tag
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setParameterName($xml);
        $this->setSecret($xml);
        $this->setExpirationTime($xml);
        $this->setIsHttpOnly($xml);
        $this->setIsHttpsOnly($xml);
        $this->setSameSite($xml);
    }

    /**
     * Detects the remember-me cookie name based on 'parameter_name' tag attribute
     *
     * Uses DEFAULT_PARAMETER_NAME when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     */
    private function setParameterName(\SimpleXMLElement $xml): void
    {
        $this->parameterName = !empty($xml["parameter_name"])?(string) $xml["parameter_name"]:self::DEFAULT_PARAMETER_NAME;
    }

    /**
     * Gets the remember-me cookie name
     *
     * @return string
     */
    public function getParameterName(): string
    {
        return $this->parameterName;
    }

    /**
     * Detects the token encryption secret based on 'secret' tag attribute
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new ConfigurationException("Attribute 'secret' must be set for tag 'remember_me'");
        }
        $this->secret = (string) $xml["secret"];
    }

    /**
     * Gets the token encryption secret
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Detects token lifetime in seconds based on 'expiration' tag attribute
     *
     * Uses DEFAULT_EXPIRATION_TIME when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     * @throws ConfigurationException If provided but not a positive integer
     */
    protected function setExpirationTime(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["expiration"])) {
            $this->expiration = self::DEFAULT_EXPIRATION_TIME;
        } else {
            $validator = new FieldValidator();
            $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
        }
    }

    /**
     * Detects the cookie HttpOnly flag based on the optional 'is_http_only' tag attribute
     *
     * Accepts 0 for false and 1 for true; leaves the flag unset when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     * @throws ConfigurationException If provided but not an integer 0 or 1
     */
    private function setIsHttpOnly(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["is_http_only"])) {
            return;
        } else {
            $validator = new FieldValidator();
            $this->isHttpOnly = $validator->getValidBoolean($xml, "is_http_only");
        }
    }

    /**
     * Gets the cookie HttpOnly flag, or null when the attribute was absent
     *
     * @return ?bool
     */
    public function getIsHttpOnly(): ?bool
    {
        return $this->isHttpOnly;
    }

    /**
     * Detects the cookie Secure flag based on the optional 'is_https_only' tag attribute
     *
     * Accepts 0 for false and 1 for true; leaves the flag unset when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     * @throws ConfigurationException If provided but not an integer 0 or 1
     */
    private function setIsHttpsOnly(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["is_https_only"])) {
            return;
        } else {
            $validator = new FieldValidator();
            $this->isHttpsOnly = $validator->getValidBoolean($xml, "is_https_only");
        }
    }

    /**
     * Gets the cookie Secure flag, or null when the attribute was absent
     *
     * @return ?bool
     */
    public function getIsHttpsOnly(): ?bool
    {
        return $this->isHttpsOnly;
    }

    /**
     * Detects the cookie SameSite option based on the optional 'same_site' tag attribute
     *
     * @param \SimpleXMLElement $xml The remember_me XML tag
     * @throws ConfigurationException If provided but not None, Strict or Lax
     */
    private function setSameSite(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["same_site"])) {
            return;
        } else {
            $validator = new FieldValidator();
            $this->sameSite = $validator->getValidEnum($xml, "same_site", CookieSameSiteOptions::class);
        }
    }

    /**
     * Gets the cookie SameSite option, or null when the attribute was absent
     *
     * @return ?CookieSameSiteOptions
     */
    public function getSameSite(): ?CookieSameSiteOptions
    {
        return $this->sameSite;
    }
}