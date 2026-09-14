<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Encapsulates parsing of the security > csrf XML tag
 */
final class Csrf
{
    public const DEFAULT_EXPIRATION_TIME = 10*60;
    private string $secret;
    private int $expiration;

    /**
     * Sets up object state from the security XML tag
     *
     * @param \SimpleXMLElement $xml The security XML tag
     * @throws Exception If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->csrf)) {
            throw new Exception("Tag 'csrf', child of 'security' is required!");
        }
        $subXML = $xml->csrf;

        $this->setSecret($subXML);
        $this->setExpirationTime($subXML);
    }

    /**
     * Detects the CSRF token encryption secret based on 'secret' tag attribute
     *
     * @param \SimpleXMLElement $xml The csrf XML tag
     * @throws Exception If the attribute is missing or empty
     */
    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new Exception("Attribute 'secret' must be set for tag 'csrf'");
        }
        $this->secret = (string) $xml["secret"];
    }

    /**
     * Gets the CSRF token encryption secret
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Detects CSRF token lifetime in seconds based on 'expiration' tag attribute
     *
     * Uses DEFAULT_EXPIRATION_TIME when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The csrf XML tag
     * @throws Exception If provided but not a positive integer
     */
    private function setExpirationTime(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["expiration"])) {
            $this->expiration = self::DEFAULT_EXPIRATION_TIME;
        } else {
            $validator = new FieldValidator();
            $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
        }
    }

    /**
     * Gets CSRF token lifetime in seconds
     *
     * @return int
     */
    public function getExpirationTime(): int
    {
        return $this->expiration;
    }
}
