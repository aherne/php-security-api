<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

abstract class AbstractPersistence
{
    protected ?int $expiration = null;

    protected function setExpirationTime(\SimpleXMLElement $xml): void
    {
        $this->expiration = !empty($xml["expiration"])?(int) $xml["expiration"]:null;
    }

    public function getExpirationTime(): ?int
    {
        return $this->expiration;
    }
}