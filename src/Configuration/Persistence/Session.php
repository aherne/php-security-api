<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\FieldValidator;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;

/**
 * Encapsulates parsing of the security > persistence > session XML tag
 */
final class Session extends AbstractPersistence
{
    public const DEFAULT_PARAMETER_NAME = "uid";
    private string $parameterName;
    private ?bool $isHttpOnly = null;
    private ?bool $isHttpsOnly = null;
    private ?CookieSameSiteOptions $sameSite = null;
    private ?string $handler = null;

    /**
     * Sets up object state from the session XML tag
     *
     * @param \SimpleXMLElement $xml The session XML tag
     * @throws \Lucinda\WebSecurity\Configuration\Exception If an optional setting is invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setParameterName($xml);
        $this->setExpirationTime($xml);
        $this->setIsHttpOnly($xml);
        $this->setIsHttpsOnly($xml);
        $this->setSameSite($xml);
        $this->setHandler($xml);
    }

    /**
     * Detects the session cookie name based on 'parameter_name' tag attribute
     *
     * Uses DEFAULT_PARAMETER_NAME when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The session XML tag
     */
    private function setParameterName(\SimpleXMLElement $xml): void
    {
        $this->parameterName = !empty($xml["parameter_name"])?(string) $xml["parameter_name"]:self::DEFAULT_PARAMETER_NAME;
    }

    /**
     * Gets the session cookie name
     *
     * @return string
     */
    public function getParameterName(): string
    {
        return $this->parameterName;
    }

    /**
     * Detects the cookie HttpOnly flag based on the optional 'is_http_only' tag attribute
     *
     * Accepts 0 for false and 1 for true; leaves the flag unset when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The session XML tag
     * @throws \Lucinda\WebSecurity\Configuration\Exception If provided but not an integer 0 or 1
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
     * @param \SimpleXMLElement $xml The session XML tag
     * @throws \Lucinda\WebSecurity\Configuration\Exception If provided but not an integer 0 or 1
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
     * @param \SimpleXMLElement $xml The session XML tag
     * @throws \Lucinda\WebSecurity\Configuration\Exception If provided but not None, Strict or Lax
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

    /**
     * Detects the custom session save handler class based on 'handler' tag attribute
     *
     * @param \SimpleXMLElement $xml The session XML tag
     */
    private function setHandler(\SimpleXMLElement $xml): void
    {
        $this->handler = !empty($xml["handler"])?(string) $xml["handler"]:null;
    }

    /**
     * Gets the custom session save handler class name, or null when none was configured
     *
     * @return ?string
     */
    public function getHandler(): ?string
    {
        return $this->handler;
    }
}