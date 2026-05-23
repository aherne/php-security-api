<?php

namespace Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;

final class Totp
{
    public const DEFAULT_CODE_PARAMETER = "code";
    public const DEFAULT_PERIOD = 30;
    public const DEFAULT_DIGITS = 6;
    public const DEFAULT_WINDOW = 1;

    private string $issuer;
    private string $codeParameter;
    private int $period;
    private int $digits;
    private int $window;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setIssuer($xml);
        $this->setCodeParameter($xml);
        $this->setPeriod($xml);
        $this->setDigits($xml);
        $this->setWindow($xml);
    }

    private function setIssuer(\SimpleXMLElement $xml): void
    {
        if (empty($xml["issuer"])) {
            throw new ConfigurationException("Attribute 'issuer' must be set for tag 'totp'");
        }
        $this->issuer = (string) $xml["issuer"];
    }

    public function getIssuer(): string
    {
        return $this->issuer;
    }

    private function setCodeParameter(\SimpleXMLElement $xml): void
    {
        $this->codeParameter = !empty($xml["code_param"])?(string) $xml["code_param"]:self::DEFAULT_CODE_PARAMETER;
    }

    public function getCodeParameter(): string
    {
        return $this->codeParameter;
    }

    private function setPeriod(\SimpleXMLElement $xml): void
    {
        $this->period = !empty($xml["period"])?(int) $xml["period"]:self::DEFAULT_PERIOD;
        if ($this->period < 1) {
            throw new ConfigurationException("Attribute 'period' must be positive for tag 'totp'");
        }
    }

    public function getPeriod(): int
    {
        return $this->period;
    }

    private function setDigits(\SimpleXMLElement $xml): void
    {
        $this->digits = !empty($xml["digits"])?(int) $xml["digits"]:self::DEFAULT_DIGITS;
        if (!in_array($this->digits, [6, 7, 8])) {
            throw new ConfigurationException("Attribute 'digits' must be one of: 6, 7, 8");
        }
    }

    public function getDigits(): int
    {
        return $this->digits;
    }

    private function setWindow(\SimpleXMLElement $xml): void
    {
        $this->window = isset($xml["window"])?(int) $xml["window"]:self::DEFAULT_WINDOW;
        if ($this->window < 0) {
            throw new ConfigurationException("Attribute 'window' must not be negative for tag 'totp'");
        }
    }

    public function getWindow(): int
    {
        return $this->window;
    }
}
