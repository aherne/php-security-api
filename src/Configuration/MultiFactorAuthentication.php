<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp;
use Lucinda\WebSecurity\DAO\MultiFactorAuthentication as MultiFactorAuthenticationDAO;
use Lucinda\WebSecurity\DAO\Throttler\MultiFactorAuthentication as MFALoginThrottler;

/**
 * Encapsulates parsing of the security > multi_factor_authentication XML tag
 */
final class MultiFactorAuthentication
{
    private string $dao;
    private string $throttler;
    private int $expiration;
    private int $pendingExpiration;
    private string $challengeRoute;
    private string $setupRoute;
    private string $successRoute;
    private string $failureRoute;
    private string $throttledRoute;
    private Totp $method;

    /**
     * Sets up object state from the security XML tag
     *
     * @param \SimpleXMLElement $xml The security XML tag
     * @throws Exception If a required setting is missing or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->multi_factor_authentication)) {
            throw new Exception("Tag 'multi_factor_authentication', child of 'security' is required!");
        }
        $subXML = $xml->multi_factor_authentication;

        $this->setDAO($subXML);
        $this->setThrottler($subXML);
        $this->setExpiration($subXML);
        $this->setPendingExpiration($subXML);
        $this->setChallengeRoute($subXML);
        $this->setSetupRoute($subXML);
        $this->setSuccessRoute($subXML);
        $this->setFailureRoute($subXML);
        $this->setThrottledRoute($subXML);
        $this->setMethod($subXML);
    }

    /**
     * Detects DAO\MultiFactorAuthentication class based on 'dao' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If missing or the class does not implement MultiFactorAuthenticationDAO
     */
    private function setDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["dao"];
        if (empty($daoClass)) {
            throw new Exception("Attribute 'dao' must be set for tag 'multi_factor_authentication'");
        }
        if (!is_subclass_of($daoClass, MultiFactorAuthenticationDAO::class)) {
            throw new Exception("DAO must be instance of ".MultiFactorAuthenticationDAO::class);
        }
        $this->dao = $daoClass;
    }

    /**
     * Gets detected DAO\MultiFactorAuthentication class name
     *
     * @return class-string<MultiFactorAuthenticationDAO>
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Detects DAO\Throttler\MultiFactorAuthentication class based on 'throttler' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If missing or the class does not implement MFALoginThrottler
     */
    private function setThrottler(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["throttler"];
        if (empty($daoClass)) {
            throw new Exception("Attribute 'throttler' must be set for tag 'multi_factor_authentication'");
        }
        if (!is_subclass_of($daoClass, MFALoginThrottler::class)) {
            throw new Exception("Throttler DAO must be instance of ".MFALoginThrottler::class);
        }
        $this->throttler = $daoClass;
    }

    /**
     * Gets detected DAO\Throttler\MultiFactorAuthentication class name
     *
     * @return class-string<MFALoginThrottler>
     */
    public function getThrottler(): string
    {
        return $this->throttler;
    }

    /**
     * Detects successful MFA lifetime in seconds based on 'expiration' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If missing or not a positive integer
     */
    private function setExpiration(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["expiration"])) {
            throw new Exception("Attribute 'expiration' is mandatory for tag 'multi_factor_authentication'");
        } else {
            $validator = new FieldValidator();
            $this->expiration = $validator->getValidInteger($xml, "expiration", 1);
        }
    }

    /**
     * Gets the lifetime in seconds for which successful MFA remains fresh
     *
     * @return int
     */
    public function getExpiration(): int
    {
        return $this->expiration;
    }

    /**
     * Detects pending MFA lifetime in seconds based on 'pending_expiration' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If missing or not a positive integer
     */
    private function setPendingExpiration(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["pending_expiration"])) {
            throw new Exception("Attribute 'pending_expiration' is mandatory for tag 'multi_factor_authentication'");
        } else {
            $validator = new FieldValidator();
            $this->pendingExpiration = $validator->getValidInteger($xml, "pending_expiration", 1);
        }
    }

    /**
     * Gets the time in seconds allowed to complete pending MFA
     *
     * @return int
     */
    public function getPendingExpiration(): int
    {
        return $this->pendingExpiration;
    }

    /**
     * Detects MFA challenge route based on 'challenge_route' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If the attribute is missing or empty
     */
    private function setChallengeRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["challenge_route"])) {
            throw new Exception("Attribute 'challenge_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->challengeRoute = (string) $xml["challenge_route"];
    }

    /**
     * Gets MFA challenge route
     *
     * @return string
     */
    public function getChallengeRoute(): string
    {
        return $this->challengeRoute;
    }

    /**
     * Detects MFA enrollment route based on 'setup_route' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If the attribute is missing or empty
     */
    private function setSetupRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["setup_route"])) {
            throw new Exception("Attribute 'setup_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->setupRoute = (string) $xml["setup_route"];
    }

    /**
     * Gets MFA enrollment route
     *
     * @return string
     */
    public function getSetupRoute(): string
    {
        return $this->setupRoute;
    }

    /**
     * Detects MFA success route based on 'success_route' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If the attribute is missing or empty
     */
    private function setSuccessRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["success_route"])) {
            throw new Exception("Attribute 'success_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->successRoute = (string) $xml["success_route"];
    }

    /**
     * Gets MFA success route
     *
     * @return string
     */
    public function getSuccessRoute(): string
    {
        return $this->successRoute;
    }

    /**
     * Detects MFA failure route based on 'failure_route' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If the attribute is missing or empty
     */
    private function setFailureRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["failure_route"])) {
            throw new Exception("Attribute 'failure_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->failureRoute = (string) $xml["failure_route"];
    }

    /**
     * Gets MFA failure route
     *
     * @return string
     */
    public function getFailureRoute(): string
    {
        return $this->failureRoute;
    }

    /**
     * Detects MFA throttling route based on 'throttled_route' tag attribute
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If the attribute is missing or empty
     */
    private function setThrottledRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["throttled_route"])) {
            throw new Exception("Attribute 'throttled_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->throttledRoute = (string) $xml["throttled_route"];
    }

    /**
     * Gets MFA throttling route
     *
     * @return string
     */
    public function getThrottledRoute(): string
    {
        return $this->throttledRoute;
    }

    /**
     * Detects TOTP configuration from the required 'totp' child tag
     *
     * @param \SimpleXMLElement $xml The multi_factor_authentication XML tag
     * @throws Exception If the child tag is missing or its configuration is invalid
     */
    private function setMethod(\SimpleXMLElement $xml): void
    {
        if (!isset($xml->totp)) {
            throw new Exception("Child tag 'totp' must be set for tag 'multi_factor_authentication'");
        }
        $this->method = new Totp($xml->totp);
    }

    /**
     * Gets detected TOTP configuration
     *
     * @return Totp
     */
    public function getMethod(): Totp
    {
        return $this->method;
    }
}
