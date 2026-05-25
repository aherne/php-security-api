<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

/**
 * Encapsulates AbstractPersistence logic.
 */
abstract class AbstractPersistence
{
    protected ?int $expiration = null;

    /**
     * Sets expiration time.
     *
     * @param \SimpleXMLElement $xml
     */
    protected function setExpirationTime(\SimpleXMLElement $xml): void
    {
        $this->expiration = !empty($xml["expiration"])?(int) $xml["expiration"]:null;
    }

    /**
     * Gets expiration time.
     *
     * @return ?int
     */
    public function getExpirationTime(): ?int
    {
        return $this->expiration;
    }
}