<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Form;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

final class Logout
{
    private string $pageSource;
    private string $targetSuccess;
    private string $targetFailure;
    
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setPageSource($xml);
        $this->setTargetSuccess($xml);
        $this->setTargetFailure($xml);
    }

    private function setPageSource(\SimpleXMLElement $xml): void
    {
        if (empty($xml["page"])) {
            throw new ConfigurationException("Attribute 'page' must be set for tag 'logout'");
        }
        $this->pageSource = (string) $xml["page"];
    }

    public function getPageSource(): string
    {
        return $this->pageSource;
    }

    private function setTargetSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_success"])) {
            throw new ConfigurationException("Attribute 'target_success' must be set for tag 'logout'");
        }
        $this->targetSuccess = (string) $xml["target_success"];
    }

    public function getTargetSuccess(): string
    {
        return $this->targetSuccess;
    }

    private function setTargetFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_failure"])) {
            throw new ConfigurationException("Attribute 'target_failure' must be set for tag 'logout'");
        }
        $this->targetFailure = (string) $xml["target_failure"];
    }

    public function getTargetFailure(): string
    {
        return $this->targetFailure;
    }
}
