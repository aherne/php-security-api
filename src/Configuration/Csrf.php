<?php

namespace Lucinda\WebSecurity\Configuration;

/**
 * Encapsulates Csrf logic.
 */
final class Csrf
{
    public const DEFAULT_EXPIRATION_TIME = 10*60;
    private string $secret;
    private int $expiration;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
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
        if (!isset($xml["expiration"])) {
            $this->expiration = self::DEFAULT_EXPIRATION_TIME;
        } else {
            $validator = new FieldValidator();
            $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
        }
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
