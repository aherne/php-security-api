<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

/**
 * Encapsulates common parsing of security > authentication XML tag children
 */
abstract class Generic
{
    protected string $targetSuccess;
    protected string $targetFailure;

    /**
     * Sets target success route based on 'target_success' tag attribute
     *
     * @param \SimpleXMLElement $xml The authentication method XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    protected function setTargetSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_success"])) {
            throw new ConfigurationException("Attribute 'target_success' is mandatory for 'authentication' sub-tags");
        }
        $this->targetSuccess = (string) $xml["target_success"];
    }

    /**
     * Gets target success route
     *
     * @return string
     */
    public function getTargetSuccess(): string
    {
        return $this->targetSuccess;
    }

    /**
     * Sets target failure route based on 'target_failure' tag attribute
     *
     * @param \SimpleXMLElement $xml The authentication method XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    protected function setTargetFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_failure"])) {
            throw new ConfigurationException("Attribute 'target_failure' is mandatory for 'authentication' sub-tags");
        }
        $this->targetFailure = (string) $xml["target_failure"];
    }

    /**
     * Gets target failure route
     *
     * @return string
     */
    public function getTargetFailure(): string
    {
        return $this->targetFailure;
    }
}