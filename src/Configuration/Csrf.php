<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Encapsulates Csrf logic.
 */
final class Csrf
{
    public const DEFAULT_EXPIRATION = 10*60;
    private string $secret;
    private int $expiration;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $subXML = $xml->csrf;
        if (empty($subXML)) {
            throw new Exception("Tag 'csrf', child of 'security' is required!");
        }

        $this->setSecret($subXML);
        $this->setExpirationTime($subXML);
    }

    /**
     * Sets secret.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new Exception("Attribute 'secret' must be set for tag 'csrf'");
        }
        $this->secret = (string) $xml["secret"];
    }

    /**
     * Gets secret.
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Sets expiration time.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setExpirationTime(\SimpleXMLElement $xml): void
    {
        $this->expiration = !empty($xml["expiration"])?(int) $xml["expiration"]:self::DEFAULT_EXPIRATION;
    }

    /**
     * Gets expiration time.
     *
     * @return int
     */
    public function getExpirationTime(): int
    {
        return $this->expiration;
    }
}
