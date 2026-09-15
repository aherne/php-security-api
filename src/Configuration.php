<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\Configuration\Authentication;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Configuration\Exception as ConfigurationException;
use Lucinda\WebSecurity\Configuration\Persistence;
use Lucinda\WebSecurity\Configuration\Authorization;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;

/**
 * Parses and exposes the complete XML security configuration
 *
 * The supplied document must contain a top-level `security` element. Its
 * persistence, CSRF, authentication, and authorization sections are parsed
 * eagerly during construction. Multi-factor authentication is optional and
 * is represented by null when its section is absent.
 *
 * This object contains immutable configuration value objects only. It does
 * not construct application DAOs, inspect a request, or execute any security
 * workflow.
 *
 * @see Wrapper
 * @see \Lucinda\WebSecurity\Configuration\Persistence
 * @see \Lucinda\WebSecurity\Configuration\Authentication
 * @see \Lucinda\WebSecurity\Configuration\MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\Configuration\Authorization
 */
final class Configuration
{
    /**
     * Parsed authenticated-state persistence configuration
     */
    private Persistence $persistence;

    /**
     * Parsed CSRF-token configuration
     */
    private Csrf $csrf;

    /**
     * Parsed primary-authentication configuration
     */
    private Authentication $authentication;

    /**
     * Parsed resource-authorization configuration
     */
    private Authorization $authorization;

    /**
     * Parsed MFA configuration, or null when MFA is not configured
     */
    private ?MultiFactorAuthentication $multiFactorAuthentication = null;

    /**
     * Parses all configured security sections
     *
     * Child configuration objects validate their required tags, attributes,
     * class contracts, and numeric options as they are constructed.
     *
     * @param \SimpleXMLElement $xml Complete application XML document containing a `security` child
     * @throws ConfigurationException If `security` or any mandatory security setting is absent or invalid
     */
    public function __construct(\SimpleXMLElement $xml)
    {
        if (empty($xml->security)) {
            throw new ConfigurationException("Tag 'security' is mandatory!");
        }
        $mainXML = $xml->security;
        $this->persistence = new Persistence($mainXML);
        $this->csrf = new Csrf($mainXML);
        $this->authentication = new Authentication($mainXML);
        $this->authorization = new Authorization($mainXML);
        if (isset($mainXML->multi_factor_authentication)) {
            $this->multiFactorAuthentication = new MultiFactorAuthentication($mainXML);
        }
    }

    /**
     * Gets authenticated-state persistence configuration
     *
     * @return Persistence Parsed persistence drivers in configured precedence order
     */
    public function getPersistence(): Persistence
    {
        return $this->persistence;
    }

    /**
     * Gets CSRF-token configuration
     *
     * @return Csrf Parsed CSRF secret and expiration policy
     */
    public function getCsrf(): Csrf
    {
        return $this->csrf;
    }

    /**
     * Gets primary-authentication configuration
     *
     * @return Authentication Parsed form and/or OAuth2 authentication methods
     */
    public function getAuthentication(): Authentication
    {
        return $this->authentication;
    }

    /**
     * Gets resource-authorization configuration
     *
     * @return Authorization Parsed DAO-based or route-role authorization method
     */
    public function getAuthorization(): Authorization
    {
        return $this->authorization;
    }

    /**
     * Gets optional multi-factor-authentication configuration
     *
     * @return MultiFactorAuthentication|null Parsed MFA policy, or null when no MFA section was supplied
     */
    public function getMultiFactorAuthentication(): ?MultiFactorAuthentication
    {
        return $this->multiFactorAuthentication;
    }
}
