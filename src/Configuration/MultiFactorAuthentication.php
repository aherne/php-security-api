<?php

namespace Lucinda\WebSecurity\Configuration;

use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp;
use Lucinda\WebSecurity\DAO\MultiFactorAuthentication as MultiFactorAuthenticationDAO;

final class MultiFactorAuthentication
{
    private string $dao;
    private string $challengeRoute;
    private string $setupRoute;
    private string $successRoute;
    private string $failureRoute;
    private string $throttledRoute;
    private Totp $method;

    public function __construct(\SimpleXMLElement $xml)
    {
        $subXML = $xml->multi_factor_authentication;
        if (empty($subXML)) {
            throw new Exception("Tag 'multi_factor_authentication', child of 'security' is required!");
        }

        $this->setDAO($subXML);
        $this->setChallengeRoute($subXML);
        $this->setSetupRoute($subXML);
        $this->setSuccessRoute($subXML);
        $this->setFailureRoute($subXML);
        $this->setThrottledRoute($subXML);
        $this->setMethod($subXML);
    }

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

    public function getDAO(): string
    {
        return $this->dao;
    }

    private function setChallengeRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["challenge_route"])) {
            throw new Exception("Attribute 'challenge_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->challengeRoute = (string) $xml["challenge_route"];
    }

    public function getChallengeRoute(): string
    {
        return $this->challengeRoute;
    }

    private function setSetupRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["setup_route"])) {
            throw new Exception("Attribute 'setup_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->setupRoute = (string) $xml["setup_route"];
    }

    public function getSetupRoute(): string
    {
        return $this->setupRoute;
    }

    private function setSuccessRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["success_route"])) {
            throw new Exception("Attribute 'success_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->successRoute = (string) $xml["success_route"];
    }

    public function getSuccessRoute(): string
    {
        return $this->successRoute;
    }

    private function setFailureRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["failure_route"])) {
            throw new Exception("Attribute 'failure_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->failureRoute = (string) $xml["failure_route"];
    }

    public function getFailureRoute(): string
    {
        return $this->failureRoute;
    }

    private function setThrottledRoute(\SimpleXMLElement $xml): void
    {
        if (empty($xml["throttled_route"])) {
            throw new Exception("Attribute 'throttled_route' must be set for tag 'multi_factor_authentication'");
        }
        $this->throttledRoute = (string) $xml["throttled_route"];
    }

    public function getThrottledRoute(): string
    {
        return $this->throttledRoute;
    }

    private function setMethod(\SimpleXMLElement $xml): void
    {
        if (empty($xml->totp)) {
            throw new Exception("Child tag 'totp' must be set for tag 'multi_factor_authentication'");
        }
        $this->method = new Totp($xml->totp);
    }

    public function getMethod(): Totp
    {
        return $this->method;
    }
}
