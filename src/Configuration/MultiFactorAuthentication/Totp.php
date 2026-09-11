<?php

namespace Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\FieldValidator;

/**
 * Encapsulates Totp logic.
 */
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

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setIssuer($xml);
        $this->setCodeParameter($xml);
        $this->setPeriod($xml);
        $this->setDigits($xml);
        $this->setWindow($xml);
    }

    /**
     * Sets issuer.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setIssuer(\SimpleXMLElement $xml): void
    {
        if (empty($xml["issuer"])) {
            throw new ConfigurationException("Attribute 'issuer' must be set for tag 'totp'");
        }
        $this->issuer = (string) $xml["issuer"];
    }

    /**
     * Gets issuer.
     *
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Sets code parameter.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setCodeParameter(\SimpleXMLElement $xml): void
    {
        $this->codeParameter = !empty($xml["code_param"])?(string) $xml["code_param"]:self::DEFAULT_CODE_PARAMETER;
    }

    /**
     * Gets code parameter.
     *
     * @return string
     */
    public function getCodeParameter(): string
    {
        return $this->codeParameter;
    }

    /**
     * Sets period.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setPeriod(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["period"])) {
            $this->period = self::DEFAULT_PERIOD;
        } else {
            $validator = new FieldValidator();
            $this->period = $validator->getValidInteger($xml, "period", 1);
        }
    }

    /**
     * Gets period.
     *
     * @return int
     */
    public function getPeriod(): int
    {
        return $this->period;
    }

    /**
     * Sets digits.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDigits(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["digits"])) {
            $this->digits = self::DEFAULT_DIGITS;
        } else {
            $validator = new FieldValidator();
            $digits = $validator->getValidInteger($xml, "digits", 5);
            if (!in_array($digits, [6, 7, 8])) {
                throw new ConfigurationException("Attribute 'digits' must be one of: 6, 7, 8");
            }
            $this->digits = $digits;
        }
    }

    /**
     * Gets digits.
     *
     * @return int
     */
    public function getDigits(): int
    {
        return $this->digits;
    }

    /**
     * Sets window.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setWindow(\SimpleXMLElement $xml): void
    {
        if (empty($xml["window"])) {
            $this->window = self::DEFAULT_WINDOW;
        } else {
            $validator = new FieldValidator();
            $this->window = $validator->getValidInteger($xml, "window", 0);
        }
    }

    /**
     * Gets window.
     *
     * @return int
     */
    public function getWindow(): int
    {
        return $this->window;
    }
}
