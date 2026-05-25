<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

/**
 * Encapsulates Session logic.
 */
final class Session extends AbstractPersistence
{
    public const DEFAULT_PARAMETER_NAME = "uid";
    private string $parameterName;
    private ?bool $isHttpOnly;
    private ?bool $isHttpsOnly;
    private ?string $sameSite;
    private ?string $handler;

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
        $this->isHttpOnly = isset($xml["is_http_only"])?(bool) ((int) $xml["is_http_only"]):null;
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
        $this->isHttpsOnly = isset($xml["is_https_only"])?(bool) ((int) $xml["is_https_only"]):null;
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
        $this->sameSite = !empty($xml["same_site"])?(string) $xml["same_site"]:null;
    }

    /**
     * Gets same site.
     *
     * @return ?string
     */
    public function getSameSite(): ?string
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