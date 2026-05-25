<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Form;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

/**
 * Encapsulates Logout logic.
 */
final class Logout
{
    private string $pageSource;
    private string $targetSuccess;
    private string $targetFailure;
    
    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setPageSource($xml);
        $this->setTargetSuccess($xml);
        $this->setTargetFailure($xml);
    }

    /**
     * Sets page source.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPageSource(\SimpleXMLElement $xml): void
    {
        if (empty($xml["page"])) {
            throw new ConfigurationException("Attribute 'page' must be set for tag 'logout'");
        }
        $this->pageSource = (string) $xml["page"];
    }

    /**
     * Gets page source.
     *
     * @return string
     */
    public function getPageSource(): string
    {
        return $this->pageSource;
    }

    /**
     * Sets target success.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_success"])) {
            throw new ConfigurationException("Attribute 'target_success' must be set for tag 'logout'");
        }
        $this->targetSuccess = (string) $xml["target_success"];
    }

    /**
     * Gets target success.
     *
     * @return string
     */
    public function getTargetSuccess(): string
    {
        return $this->targetSuccess;
    }

    /**
     * Sets target failure.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_failure"])) {
            throw new ConfigurationException("Attribute 'target_failure' must be set for tag 'logout'");
        }
        $this->targetFailure = (string) $xml["target_failure"];
    }

    /**
     * Gets target failure.
     *
     * @return string
     */
    public function getTargetFailure(): string
    {
        return $this->targetFailure;
    }
}
