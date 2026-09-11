<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\FieldValidator;
use Lucinda\WebSecurity\PersistenceDrivers\CookieSameSiteOptions;

/**
 * Encapsulates Session logic.
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
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
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
     * Sets parameter name.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setParameterName(\SimpleXMLElement $xml): void
    {
        $this->parameterName = !empty($xml["parameter_name"])?(string) $xml["parameter_name"]:self::DEFAULT_PARAMETER_NAME;
    }

    /**
     * Gets parameter name.
     *
     * @return string
     */
    public function getParameterName(): string
    {
        return $this->parameterName;
    }

    /**
     * Sets is http only.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets is http only.
     *
     * @return ?bool
     */
    public function getIsHttpOnly(): ?bool
    {
        return $this->isHttpOnly;
    }

    /**
     * Sets is https only.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets is https only.
     *
     * @return ?bool
     */
    public function getIsHttpsOnly(): ?bool
    {
        return $this->isHttpsOnly;
    }

    /**
     * Sets same site.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets same site.
     *
     * @return ?CookieSameSiteOptions
     */
    public function getSameSite(): ?CookieSameSiteOptions
    {
        return $this->sameSite;
    }

    /**
     * Sets handler.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setHandler(\SimpleXMLElement $xml): void
    {
        $this->handler = !empty($xml["handler"])?(string) $xml["handler"]:null;
    }

    /**
     * Gets handler.
     *
     * @return ?string
     */
    public function getHandler(): ?string
    {
        return $this->handler;
    }
}