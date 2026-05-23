<?php
namespace Lucinda\WebSecurity\Security;

use Lucinda\WebSecurity\Configuration\Authorization as ConfigurationAuthorization;
use Lucinda\WebSecurity\Configuration\Authorization\ByDAO as ConfigurationAuthorizationByDAO;
use Lucinda\WebSecurity\Configuration\Authorization\ByXML as ConfigurationAuthorizationByXML;
use Lucinda\WebSecurity\Security\Authorization\ByDao as AuthorizatorByDAO;
use Lucinda\WebSecurity\Security\Authorization\ByXML as AuthorizatorByXML;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Exception as SecurityException;

final class Authorization
{
    private Result|null $outcome = null;

    public function __construct(
        ConfigurationAuthorization $configuration,
        Request $request,
        int|string|null $userID,
        ?\SimpleXMLElement $routes = null
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
                $this->outcome = $this->authenticateByXML($subConfiguration, $request, $userID, $routes);
            }
        }
    }

    private function authenticateByDAO(
        ConfigurationAuthorizationByDAO $configuration,
        Request $request,
        int|string|null $userID
        )
    {
        $authenticator = new AuthorizatorByDAO($configuration, $request, $userID);
        return $authenticator->getResult();
    }

    private function authenticateByXML(
        ConfigurationAuthorizationByXML $configuration,
        Request $request,
        int|string|null $userID,
        ?\SimpleXMLElement $routes = null
        )
    {
        if ($routes === null) {
            throw new SecurityException("XML based authorization requires preconfigured routes");
        }

        $authenticator = new AuthorizatorByXML($configuration, $request, $userID, $routes);
        return $authenticator->getResult();
    }

    public function getOutcome(): Result|null
    {
        return $this->outcome;
    }
}
