<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

abstract class Generic
{
    protected string $targetSuccess;
    protected string $targetFailure;

    /**
     * Sets target success route
     *
     * @param \SimpleXMLElement $xml
     */
    protected function setTargetSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_success"])) {
            throw new ConfigurationException("Attribute 'target_success' is mandatory 'authentication' sub-tags");
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
     * Sets target failure route
     *
     * @param \SimpleXMLElement $xml
     */
    protected function setTargetFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_failure"])) {
            throw new ConfigurationException("Attribute 'target_failure' is mandatory 'authentication' sub-tags");
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