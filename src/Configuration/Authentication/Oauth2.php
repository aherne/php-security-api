<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Provisioning;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\DAO\OAuth2\Login as Oauth2Login;
use Lucinda\WebSecurity\DAO\OAuth2\ApprovalProvisioning as Oauth2ApprovalProvisioning;
use Lucinda\WebSecurity\DAO\OAuth2\AutomaticProvisioning as Oauth2AutomaticProvisioning;

/**
 * Encapsulates OAuth2 logic.
 */
final class Oauth2 extends Generic
{
    private string $dao;
    private array $drivers = [];
    private Provisioning $provisioning;
    private string $targetPending = "";
    private int $stateExpiration;

    /**
     * Sets up object state.
     *
     * @param \SimpleXMLElement $xml
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        $this->setProvisioning($xml);
        $this->setDAO($xml);
        $this->setTargetSuccess($xml);
        $this->setTargetFailure($xml);
        $this->setTargetPending($xml);
        $this->setStateExpiration($xml);
        $this->setDrivers($xml);
    }

    /**
     * Sets how the state machine will treat accounts attempting OAuth2 login
     * 
     * @param \SimpleXMLElement $xml
     * @throws ConfigurationException
     * @return void
     */
    private function setProvisioning(\SimpleXMLElement $xml): void
    {
        $provisioning = (string) $xml["provisioning"];
        if (empty($provisioning)) {
            throw new ConfigurationException("Attribute 'provisioning' must be set for tag 'oauth2'");
        }
        if (Provisioning::tryFrom($provisioning) === null) {
            throw new ConfigurationException("Attribute 'provisioning' has invalid value");
        }
        $this->provisioning = Provisioning::from($provisioning);
    }

    /**
     * Gets how the state machine will treat accounts attempting OAuth2 login
     * 
     * @return Provisioning
     */
    public function getProvisioning(): Provisioning
    {
        return $this->provisioning;
    }

    /**
     * Sets DAO.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDAO(\SimpleXMLElement $xml): void
    {
        $daoClass = (string) $xml["dao"];
        $requiredDAO = match ($this->provisioning) {
            Provisioning::EXISTING_ONLY =>
                Oauth2Login::class,

            Provisioning::AUTOMATIC =>
                Oauth2AutomaticProvisioning::class,

            Provisioning::APPROVAL_REQUIRED =>
                Oauth2ApprovalProvisioning::class,
        };

        if (!is_subclass_of($daoClass, $requiredDAO)) {
            throw new ConfigurationException(
                "DAO must implement ".$requiredDAO
            );
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
     * Sets drivers.
     *
     * @param \SimpleXMLElement $xml
     */
    private function setDrivers(\SimpleXMLElement $xml): void
    {
        foreach ($xml->driver as $child) {
            $this->drivers[] = new Driver($child);
        }
        if (empty($this->drivers)) {
            throw new ConfigurationException("At least one 'driver' child tag must be set for tag 'oauth2'");
        }
    }

    /**
     * Gets drivers.
     *
     * @return array
     */
    public function getDrivers(): array
    {
        return $this->drivers;
    }

    /**
     * Sets target pending route
     *
     * @param \SimpleXMLElement $xml
     */
    private function setTargetPending(\SimpleXMLElement $xml): void
    {
        if ($this->provisioning !== Provisioning::APPROVAL_REQUIRED) {
            return; // this feature is 100% useless unless OAuth2 accounts require approval
        }
        if (empty($xml["target_pending"])) {
            throw new ConfigurationException("Attribute 'target_pending' is mandatory 'authentication' sub-tags");
        }
        $this->targetPending = (string) $xml["target_pending"];
    }

    /**
     * Gets target pending route
     *
     * @return string
     */
    public function getTargetPending(): string
    {
        return $this->targetPending;
    }

    /**
     * Sets for how long value of OAuth2 state will remain fresh
     *
     * @param \SimpleXMLElement $xml
     */
    private function setStateExpiration(\SimpleXMLElement $xml): void
    {
        $stateExpiration = filter_var(
            (string) $xml["state_expiration"],
            FILTER_VALIDATE_INT,
            ["options" => ["min_range" => 1]]
        );

        if ($stateExpiration === false) {
            throw new ConfigurationException("Attribute 'state_expiration' must have positive integer value");
        }
        $this->stateExpiration = (int) $stateExpiration;
    }

    /**
     * Gets for how long value of OAuth2 state will remain fresh
     *
     * @return int
     */
    public function getStateExpiration(): int
    {
        return $this->stateExpiration;
    }
}