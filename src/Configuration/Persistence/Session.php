<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

final class Session extends AbstractPersistence
{
    public const DEFAULT_PARAMETER_NAME = "uid";
    private string $parameterName;
    private ?bool $isHttpOnly;
    private ?bool $isHttpsOnly;
    private ?string $sameSite;
    private ?string $handler;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setParameterName($xml);
        $this->setExpirationTime($xml);
        $this->setIsHttpOnly($xml);
        $this->setIsHttpsOnly($xml);
        $this->setSameSite($xml);
        $this->setHandler($xml);
    }

    private function setParameterName(\SimpleXMLElement $xml): void
    {
        $this->parameterName = !empty($xml["parameter_name"])?(string) $xml["parameter_name"]:self::DEFAULT_PARAMETER_NAME;
    }

    public function getParameterName(): string
    {
        return $this->parameterName;
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

    private function setHandler(\SimpleXMLElement $xml): void
    {
        $this->handler = !empty($xml["handler"])?(string) $xml["handler"]:null;
    }

    public function getHandler(): ?string
    {
        return $this->handler;
    }
}