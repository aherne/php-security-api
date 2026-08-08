<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp;
use Lucinda\WebSecurity\DAO\MultiFactorAuthentication as MultiFactorAuthenticationDAO;
use Lucinda\WebSecurity\DAO\Throttler\MultiFactorAuthentication as MFALoginThrottler;

/**
 * Encapsulates MultiFactorAuthentication logic.
 */
final class MultiFactorAuthentication
{
    private string $dao;
    private string $throttler;
    private string $challengeRoute;
    private string $setupRoute;
    private string $successRoute;
    private string $failureRoute;
    private string $throttledRoute;
    private Totp $method;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (!isset($xml->multi_factor_authentication)) {
            throw new Exception("Tag 'multi_factor_authentication', child of 'security' is required!");
        }
        $subXML = $xml->multi_factor_authentication;

        $this->setDAO($subXML);
        $this->setThrottler($subXML);
        $this->setChallengeRoute($subXML);
        $this->setSetupRoute($subXML);
        $this->setSuccessRoute($subXML);
        $this->setFailureRoute($subXML);
        $this->setThrottledRoute($subXML);
        $this->setMethod($subXML);
    }

    /**
     * Sets DAO.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets DAO.
     *
     * @return string
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Sets throttler DAO.
     *
     * @param \SimpleXMLElement $xml
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
     * Gets throttler DAO.
     *
     * @return string
     */
    public function getThrottler(): string
    {
        return $this->throttler;
    }

    /**
     * Sets challenge route.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setChallengeRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["challenge_route"])) {
            throw new Exception("Attribute 'challenge_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->challengeRoute = (string) $xml["challenge_route"];
    }

    /**
     * Gets challenge route.
     *
     * @return string
     */
    public function getChallengeRoute(): string
    {
        return $this->challengeRoute;
    }

    /**
     * Sets setup route.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setSetupRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["setup_route"])) {
            throw new Exception("Attribute 'setup_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->setupRoute = (string) $xml["setup_route"];
    }

    /**
     * Gets setup route.
     *
     * @return string
     */
    public function getSetupRoute(): string
    {
        return $this->setupRoute;
    }

    /**
     * Sets success route.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setSuccessRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["success_route"])) {
            throw new Exception("Attribute 'success_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->successRoute = (string) $xml["success_route"];
    }

    /**
     * Gets success route.
     *
     * @return string
     */
    public function getSuccessRoute(): string
    {
        return $this->successRoute;
    }

    /**
     * Sets failure route.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setFailureRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["failure_route"])) {
            throw new Exception("Attribute 'failure_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->failureRoute = (string) $xml["failure_route"];
    }

    /**
     * Gets failure route.
     *
     * @return string
     */
    public function getFailureRoute(): string
    {
        return $this->failureRoute;
    }

    /**
     * Sets throttled route.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setThrottledRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["throttled_route"])) {
            throw new Exception("Attribute 'throttled_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->throttledRoute = (string) $xml["throttled_route"];
    }

    /**
     * Gets throttled route.
     *
     * @return string
     */
    public function getThrottledRoute(): string
    {
        return $this->throttledRoute;
    }

    /**
     * Sets method.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setMethod(\SimpleXMLElement $xml): void
    {
        if (!isset($xml->totp)) {
            throw new Exception("Child tag 'totp' must be set for tag 'multi_factor_authentication'");
        }
        $this->method = new Totp($xml->totp);
    }

    /**
     * Gets method.
     *
     * @return Totp
     */
    public function getMethod(): Totp
    {
        return $this->method;
    }
}
