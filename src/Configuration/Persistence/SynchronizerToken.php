<?php

namespace Lucinda\WebSecurity\Configuration\Persistence;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\FieldValidator;

/**
 * Encapsulates parsing of the security > persistence > synchronizer_token XML tag
 */
final class SynchronizerToken extends AbstractPersistence
{
    public const DEFAULT_EXPIRATION_TIME = 3600;
    public const DEFAULT_REGENERATION_TIME = 60;
    private string $secret;
    private int $regeneration;

    /**
     * Sets up object state from the synchronizer_token XML tag
     *
     * @param \SimpleXMLElement $xml The synchronizer_token XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setSecret($xml);
        $this->setExpirationTime($xml);
        $this->setRegenerationTime($xml);
    }

    /**
     * Detects the token encryption secret based on 'secret' tag attribute
     *
     * @param \SimpleXMLElement $xml The synchronizer_token XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setSecret(\SimpleXMLElement $xml): void
    {
        if (empty($xml["secret"])) {
            throw new ConfigurationException("Attribute 'secret' must be set for tag 'synchronizer_token'");
        }
        $this->secret = (string) $xml["secret"];
    }

    /**
     * Gets the token encryption secret
     *
     * @return string
     */
    public function getSecret(): string
    {
        return $this->secret;
    }

    /**
     * Detects token lifetime in seconds based on 'expiration' tag attribute
     *
     * Uses DEFAULT_EXPIRATION_TIME when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The synchronizer_token XML tag
     * @throws ConfigurationException If provided but not a positive integer
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
     * Detects token refresh age in seconds based on 'regeneration' tag attribute
     *
     * Uses DEFAULT_REGENERATION_TIME when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The synchronizer_token XML tag
     * @throws ConfigurationException If provided but not a positive integer
     */
    private function setRegenerationTime(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["regeneration"])) {
            $this->regeneration = self::DEFAULT_REGENERATION_TIME;
        } else {
            $validator = new FieldValidator();
            $this->regeneration = $validator->getValidInteger($xml, "regeneration", 1);
        }
    }

    /**
     * Gets the token age in seconds after which regeneration is required
     *
     * @return int
     */
    public function getRegenerationTime(): int
    {
        return $this->regeneration;
    }
}