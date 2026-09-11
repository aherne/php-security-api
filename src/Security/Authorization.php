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
 * Encapsulates Authorization logic.
 */
final class Authorization
{
    private Result|null $outcome = null;

    /**
     * Sets up object state.
     *
     * @param ConfigurationAuthorization $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param ?RolesDetector $rolesDetector
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
     * Authenticate by DAO.
     *
     * @param ConfigurationAuthorizationByDAO $configuration
     * @param Request $request
     * @param int|string|null $userID
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
     * Authenticate by x m l.
     *
     * @param ConfigurationAuthorizationByXML $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param ?RolesDetector $rolesDetector
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
     * Gets outcome.
     *
     * @return Result|null
     */
    public function getOutcome(): Result|null
    {
        return $this->outcome;
    }
}
