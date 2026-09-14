<?php

namespace Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Driver;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Provisioning;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\FieldValidator;
use Lucinda\WebSecurity\DAO\OAuth2\Login as Oauth2Login;
use Lucinda\WebSecurity\DAO\OAuth2\ApprovalProvisioning as Oauth2ApprovalProvisioning;
use Lucinda\WebSecurity\DAO\OAuth2\AutomaticProvisioning as Oauth2AutomaticProvisioning;

/**
 * Encapsulates parsing of the security > authentication > oauth2 XML tag
 */
final class Oauth2 extends Generic
{
    private string $dao;
    /**
     * @var Driver[]
     */
    private array $drivers = [];
    private Provisioning $provisioning;
    private string $targetPending = "";
    private int $stateExpiration;

    /**
     * Sets up object state from the oauth2 XML tag
     *
     * @param \SimpleXMLElement $xml The oauth2 XML tag
     * @throws ConfigurationException If a required setting is missing or invalid
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
     * Detects account creation policy based on 'provisioning' tag attribute
     *
     * @param \SimpleXMLElement $xml The oauth2 XML tag
     * @throws ConfigurationException If missing or not a supported provisioning policy
     */
    private function setProvisioning(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["provisioning"])) {
            throw new ConfigurationException("Attribute 'provisioning' is mandatory for tag 'oauth2'");
        } else {
            $validator = new FieldValidator();
            $this->provisioning = $validator->getValidEnum($xml, "provisioning", Provisioning::class);
        }
    }

    /**
     * Gets detected account creation policy
     *
     * @return Provisioning
     */
    public function getProvisioning(): Provisioning
    {
        return $this->provisioning;
    }

    /**
     * Detects the OAuth2 login DAO class based on 'dao' and 'provisioning' tag attributes
     *
     * @param \SimpleXMLElement $xml The oauth2 XML tag
     * @throws ConfigurationException If the class does not implement the interface required by the policy
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
     * Gets the OAuth2 DAO class name implementing the configured provisioning policy
     *
     * @return class-string<Oauth2Login>
     */
    public function getDAO(): string
    {
        return $this->dao;
    }

    /**
     * Detects OAuth2 provider configurations from 'driver' child tags
     *
     * @param \SimpleXMLElement $xml The oauth2 XML tag
     * @throws ConfigurationException If no driver is configured or a child configuration is invalid
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
     * Gets detected OAuth2 provider configurations
     *
     * @return Driver[]
     */
    public function getDrivers(): array
    {
        return $this->drivers;
    }

    /**
     * Detects pending approval route based on 'target_pending' tag attribute
     *
     * The attribute is used only with the approval_required provisioning policy.
     *
     * @param \SimpleXMLElement $xml The oauth2 XML tag
     * @throws ConfigurationException If approval is required and the attribute is missing or empty
     */
    private function setTargetPending(\SimpleXMLElement $xml): void
    {
        if ($this->provisioning !== Provisioning::APPROVAL_REQUIRED) {
            return; // this feature is 100% useless unless OAuth2 accounts require approval
        }
        if (empty($xml["target_pending"])) {
            throw new ConfigurationException("Attribute 'target_pending' is mandatory for tag 'oauth2'");
        }
        $this->targetPending = (string) $xml["target_pending"];
    }

    /**
     * Gets pending approval route, or an empty string when approval is not required
     *
     * @return string
     */
    public function getTargetPending(): string
    {
        return $this->targetPending;
    }

    /**
     * Detects OAuth2 state lifetime in seconds based on 'state_expiration' tag attribute
     *
     * @param \SimpleXMLElement $xml The oauth2 XML tag
     * @throws ConfigurationException If missing or not a positive integer
     */
    private function setStateExpiration(\SimpleXMLElement $xml): void
    {
        if (!isset($xml["state_expiration"])) {
            throw new ConfigurationException("Attribute 'state_expiration' is mandatory for tag 'oauth2'");
        } else {
            $validator = new FieldValidator();
            $this->stateExpiration = $validator->getValidInteger($xml, "state_expiration", 1);
        }
    }

    /**
     * Gets OAuth2 state lifetime in seconds
     *
     * @return int
     */
    public function getStateExpiration(): int
    {
        return $this->stateExpiration;
    }
}