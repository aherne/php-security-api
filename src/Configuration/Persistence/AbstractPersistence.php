<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\FieldValidator;

/**
 * Encapsulates common parsing of security > persistence XML tag children
 */
abstract class AbstractPersistence
{
    protected ?int $expiration = null;

    /**
     * Detects persistence lifetime in seconds based on the optional 'expiration' tag attribute
     *
     * Leaves expiration unset when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The persistence driver XML tag
     * @throws \Lucinda\WebSecurity\Configuration\Exception If provided but not a positive integer
     */
    protected function setExpirationTime(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["expiration"])) {
            return;
        }

        $validator = new FieldValidator();
        $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
    }

    /**
     * Gets persistence lifetime in seconds, or null when no lifetime was configured
     *
     * @return ?int
     */
    public function getExpirationTime(): ?int
    {
        return $this->expiration;
    }
}