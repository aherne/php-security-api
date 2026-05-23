<?php

namespace Lucinda\WebSecurity\Configuration;

final class Csrf
{
    public const DEFAULT_EXPIRATION = 10*60;
    private string $secret;
    private int $expiration;

    public function __construct(\SimpleXMLElement $xml)
    {
        $subXML = $xml->csrf;
        if (empty($subXML)) {
            throw new Exception("Tag 'csrf', child of 'security' is required!");
        }

        $this->setSecret($subXML);
        $this->setExpirationTime($subXML);
    }

    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new Exception("Attribute 'secret' must be set for tag 'csrf'");
        }
        $this->secret = (string) $xml["secret"];
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    private function setExpirationTime(\SimpleXMLElement $xml): void
    {
        $this->expiration = !empty($xml["expiration"])?(int) $xml["expiration"]:self::DEFAULT_EXPIRATION;
    }

    public function getExpirationTime(): int
    {
        return $this->expiration;
    }
}
