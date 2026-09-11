<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\FieldValidator;

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
        if (empty($xml["expiration"])) {
            return;
        }

        $validator = new FieldValidator();
        $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
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