<?php

namespace Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\FieldValidator;

/**
 * Encapsulates parsing of the security > multi_factor_authentication > totp XML tag
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
     * Sets up object state from the totp XML tag
     *
     * @param \SimpleXMLElement $xml The totp XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
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
     * Detects the authenticator issuer label based on 'issuer' tag attribute
     *
     * @param \SimpleXMLElement $xml The totp XML tag
     * @throws ConfigurationException If the attribute is missing or empty
     */
    private function setIssuer(\SimpleXMLElement $xml): void
    {
        if (empty($xml["issuer"])) {
            throw new ConfigurationException("Attribute 'issuer' must be set for tag 'totp'");
        }
        $this->issuer = (string) $xml["issuer"];
    }

    /**
     * Gets the issuer label used in the authenticator provisioning URI
     *
     * @return string
     */
    public function getIssuer(): string
    {
        return $this->issuer;
    }

    /**
     * Detects the POST parameter holding the TOTP code based on 'code_param' tag attribute
     *
     * Uses DEFAULT_CODE_PARAMETER when the attribute is missing or empty.
     *
     * @param \SimpleXMLElement $xml The totp XML tag
     */
    private function setCodeParameter(\SimpleXMLElement $xml): void
    {
        $this->codeParameter = !empty($xml["code_param"])?(string) $xml["code_param"]:self::DEFAULT_CODE_PARAMETER;
    }

    /**
     * Gets the POST parameter name holding the TOTP code
     *
     * @return string
     */
    public function getCodeParameter(): string
    {
        return $this->codeParameter;
    }

    /**
     * Detects TOTP time-step duration in seconds based on 'period' tag attribute
     *
     * Uses DEFAULT_PERIOD when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The totp XML tag
     * @throws ConfigurationException If provided but not a positive integer
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
     * Gets TOTP time-step duration in seconds
     *
     * @return int
     */
    public function getPeriod(): int
    {
        return $this->period;
    }

    /**
     * Detects TOTP code length based on 'digits' tag attribute
     *
     * Uses DEFAULT_DIGITS when the attribute is absent.
     *
     * @param \SimpleXMLElement $xml The totp XML tag
     * @throws ConfigurationException If provided but not an integer equal to 6, 7 or 8
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
     * Gets the number of digits in a TOTP code
     *
     * @return int
     */
    public function getDigits(): int
    {
        return $this->digits;
    }

    /**
     * Detects allowed TOTP clock drift based on 'window' tag attribute
     *
     * Counts accepted time steps before and after the current step.
     * Uses DEFAULT_WINDOW when absent; zero accepts only the current step.
     *
     * @param \SimpleXMLElement $xml The totp XML tag
     * @throws ConfigurationException If provided but not a nonnegative integer
     */
    private function setWindow(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["window"])) {
            $this->window = self::DEFAULT_WINDOW;
        } else {
            $validator = new FieldValidator();
            $this->window = $validator->getValidInteger($xml, "window", 0);
        }
    }

    /**
     * Gets the number of accepted TOTP time steps on either side of the current step
     *
     * @return int
     */
    public function getWindow(): int
    {
        return $this->window;
    }
}
