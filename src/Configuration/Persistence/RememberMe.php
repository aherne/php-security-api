<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

final class RememberMe extends AbstractPersistence
{
    public const DEFAULT_PARAMETER_NAME = "uid";
    public const DEFAULT_EXPIRATION_TIME = 24*3600;
    private string $parameterName;
    private string $secret;
    private ?bool $isHttpOnly;
    private ?bool $isHttpsOnly;
    private ?string $sameSite;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setParameterName($xml);
        $this->setSecret($xml);
        $this->setExpirationTime($xml);
        $this->setIsHttpOnly($xml);
        $this->setIsHttpsOnly($xml);
        $this->setSameSite($xml);
    }

    private function setParameterName(\SimpleXMLElement $xml): void
    {
        $this->parameterName = !empty($xml["parameter_name"])?(string) $xml["parameter_name"]:self::DEFAULT_PARAMETER_NAME;
    }

    public function getParameterName(): string
    {
        return $this->parameterName;
    }

    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new ConfigurationException("Attribute 'secret' must be set for tag 'remember_me'");
        }
        $this->secret = (string) $xml["secret"];
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    protected function setExpirationTime(\SimpleXMLElement $xml): void
    {
        $this->expiration = !empty($xml["expiration"])?(int) $xml["expiration"]:self::DEFAULT_EXPIRATION_TIME;
    }

    private function setIsHttpOnly(\SimpleXMLElement $xml): void
    {
        $this->isHttpOnly = isset($xml["is_http_only"])?(bool) ((int) $xml["is_http_only"]):null;
    }

    public function getIsHttpOnly(): ?bool
    {
        return $this->isHttpOnly;
    }

    private function setIsHttpsOnly(\SimpleXMLElement $xml): void
    {
        $this->isHttpsOnly = isset($xml["is_https_only"])?(bool) ((int) $xml["is_https_only"]):null;
    }

    public function getIsHttpsOnly(): ?bool
    {
        return $this->isHttpsOnly;
    }

    private function setSameSite(\SimpleXMLElement $xml): void
    {
        $this->sameSite = !empty($xml["same_site"])?(string) $xml["same_site"]:null;
    }

    public function getSameSite(): ?string
    {
        return $this->sameSite;
    }
}