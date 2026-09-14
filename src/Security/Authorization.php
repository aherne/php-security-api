<?php
namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\Authorization as ConfigurationAuthorization;
use Lucinda\WebSecurity\Configuration\Authorization\ByDAO as ConfigurationAuthorizationByDAO;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML as ConfigurationAuthorizationByXML;
use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Security\Authorization\ByDao as AuthorizatorByDAO;
use Lucinda\WebSecurity\Security\Authorization\ByXML as AuthorizatorByXML;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Exception as SecurityException;

/**
 * Selects the configured authorization mechanism and evaluates resource access
 *
 * Construction delegates to DAO-based or route-role authorization and retains
 * the first result. Produces an Authorization\Result, not a packet; the
 * enclosing wrapper converts denied access into a security packet.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authorization
 * @see \Lucinda\WebSecurity\Wrapper\Authorization
 * @see \Lucinda\WebSecurity\Security\Authorization\Result
 */
final class Authorization
{
    private Result|null $outcome = null;

    /**
     * Constructs and executes the configured authorization workflow
     *
     * @param ConfigurationAuthorization $configuration Parsed authorization configuration
     * @param Request $request Request whose resource access is being evaluated
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @param RolesDetector|null $rolesDetector Parsed route-role policies, required for XML-based authorization
     * @throws SecurityException If XML-based authorization lacks a roles detector
     * @throws \Throwable If a configured authorization DAO fails
     */
    public function __construct(
        ConfigurationAuthorization $configuration,
        Request $request,
        int|string|null $userID,
        ?RolesDetector $rolesDetector = null
        )
    {        
        $methods = $configuration->getMethods();
        foreach ($methods as $subConfiguration) {
            if ($this->outcome) {
                break; // outcome has already been detected
            }

            if ($subConfiguration instanceof ConfigurationAuthorizationByDAO) {
                $this->outcome = $this->authenticateByDAO($subConfiguration, $request, $userID);
            } else {
                $this->outcome = $this->authenticateByXML($subConfiguration, $request, $userID, $rolesDetector);
            }
        }
    }

    /**
     * Delegates access evaluation to the configured page and user DAOs
     *
     * @param ConfigurationAuthorizationByDAO $configuration Parsed DAO-based authorization settings
     * @param Request $request Request providing the route and HTTP method
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @return Result Authorization decision and associated failure callback
     * @throws \Throwable If an authorization DAO fails
     */
    private function authenticateByDAO(
        ConfigurationAuthorizationByDAO $configuration,
        Request $request,
        int|string|null $userID
        )
    {
        $authenticator = new AuthorizatorByDAO($configuration, $request, $userID);
        return $authenticator->getResult();
    }

    /**
     * Delegates access evaluation to the configured route-role policies
     *
     * @param ConfigurationAuthorizationByXML $configuration Parsed route-role authorization settings
     * @param Request $request Request providing the route to authorize
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @param RolesDetector|null $rolesDetector Parsed route-role policies
     * @return Result Authorization decision and associated failure callback
     * @throws SecurityException If the roles detector is missing
     * @throws \Throwable If the user-roles DAO fails
     */
    private function authenticateByXML(
        ConfigurationAuthorizationByXML $configuration,
        Request $request,
        int|string|null $userID,
        ?RolesDetector $rolesDetector = null
        )
    {
        if ($rolesDetector === null) {
            throw new SecurityException("XML based authorization requires preconfigured routes");
        }

        $authenticator = new AuthorizatorByXML($configuration, $request, $userID, $rolesDetector);
        return $authenticator->getResult();
    }

    /**
     * Gets the authorization result computed during construction
     *
     * @return Result|null Computed decision, or null when no authorization mechanism produced one
     */
    public function getOutcome(): Result|null
    {
        return $this->outcome;
    }
}
