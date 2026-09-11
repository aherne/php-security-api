<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\FieldValidator;

/**
 * Encapsulates SynchronizerToken logic.
 */
final class SynchronizerToken extends AbstractPersistence
{
    public const DEFAULT_EXPIRATION_TIME = 3600;
    public const DEFAULT_REGENERATION_TIME = 60;
    private string $secret;
    private int $regeneration;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setSecret($xml);
        $this->setExpirationTime($xml);
        $this->setRegenerationTime($xml);
    }

    /**
     * Sets secret.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new ConfigurationException("Attribute 'secret' must be set for tag 'synchronizer_token'");
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
    protected function setExpirationTime(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["expiration"])) {
            $this->expiration = self::DEFAULT_EXPIRATION_TIME;
        } else {
            $validator = new FieldValidator();
            $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
        }
    }

    /**
     * Sets regeneration time.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setRegenerationTime(\SimpleXMLElement $xml): void
    {
        if (empty($xml["regeneration"])) {
            $this->regeneration = self::DEFAULT_REGENERATION_TIME;
        } else {
            $validator = new FieldValidator();
            $this->regeneration = $validator->getValidInteger($xml, "regeneration", 1);
        }
    }

    /**
     * Gets regeneration time.
     *
     * @return int
     */
    public function getRegenerationTime(): int
    {
        return $this->regeneration;
    }
}