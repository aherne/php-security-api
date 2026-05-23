<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\Oauth2Authentication;

final class Oauth2
{
    private string $dao;
    private array $drivers = [];
    private string $pageLogout;
    private string $targetLoginSuccess;
    private string $targetLoginFailure;
    private string $targetLogoutSuccess;
    private string $targetLogoutFailure;

    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setDAO($xml);
        $this->setPageLogout($xml);
        $this->setTargetLoginSuccess($xml);
        $this->setTargetLoginFailure($xml);
        $this->setTargetLogoutSuccess($xml);
        $this->setTargetLogoutFailure($xml);
        $this->setDrivers($xml);
    }

    private function setPageLogout(\SimpleXMLElement $xml): void
    {
        if (empty($xml["logout"])) {
            throw new ConfigurationException("Attribute 'logout' must be set for tag 'oauth2'");
        }
        $this->pageLogout = (string) $xml["logout"];
    }

    public function getPageLogout(): ?string
    {
        return $this->pageLogout;
    }

    private function setTargetLoginSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_login_success"])) {
            throw new ConfigurationException("Attribute 'target_login_success' must be set for tag 'oauth2'");
        }
        $this->targetLoginSuccess = (string) $xml["target_login_success"];
    }

    public function getTargetLoginSuccess(): ?string
    {
        return $this->targetLoginSuccess;
    }

    private function setTargetLoginFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_login_failure"])) {
            throw new ConfigurationException("Attribute 'target_login_failure' must be set for tag 'oauth2'");
        }
        $this->targetLoginFailure = (string) $xml["target_login_failure"];
    }

    public function getTargetLoginFailure(): ?string
    {
        return $this->targetLoginFailure;
    }

    private function setTargetLogoutSuccess(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_logout_success"])) {
            throw new ConfigurationException("Attribute 'target_logout_success' must be set for tag 'oauth2'");
        }
        $this->targetLogoutSuccess = (string) $xml["target_logout_success"];
    }

    public function getTargetLogoutSuccess(): ?string
    {
        return $this->targetLogoutSuccess;
    }

    private function setTargetLogoutFailure(\SimpleXMLElement $xml): void
    {
        if (empty($xml["target_logout_failure"])) {
            throw new ConfigurationException("Attribute 'target_logout_failure' must be set for tag 'oauth2'");
        }
        $this->targetLogoutFailure = (string) $xml["target_logout_failure"];
    }

    public function getTargetLogoutFailure(): ?string
    {
        return $this->targetLogoutFailure;
    }

    private function setDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["dao"];
        if (empty($daoClass)) {
            throw new ConfigurationException("Attribute 'dao' must be set for tag 'oauth2'");
        }
        if (!is_subclass_of($daoClass, Oauth2Authentication::class)) {
            throw new ConfigurationException("DAO must be instance of ".Oauth2Authentication::class);
        }
        $this->dao = $daoClass;
    }

    public function getDAO(): string
    {
        return $this->dao;
    }

    private function setDrivers(\SimpleXMLElement $xml): void
    {
        foreach ($xml->driver as $child) {
            $this->drivers[] = new Driver($child);
        }
        if (empty($this->drivers)) {
            throw new ConfigurationException("At least one 'driver' child must be set for tag 'oauth2'");
        }
    }

    public function getDrivers(): array
    {
        return $this->drivers;
    }
}