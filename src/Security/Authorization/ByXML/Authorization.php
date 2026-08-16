<?php

namespace Lucinda\WebSecurity\Security\Authorization\ByXML;

use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Lucinda\WebSecurity\DAO\UserRoles;

/**
 * Encapsulates request authorization via XML that must have routes configured as:
 * <routes>
 *     <route id="{PAGE_TO_AUTHORIZE" access="ROLE_GUEST|ROLE_USER" ... />
 *     ...
 * </routes>
 */
final class Authorization
{
    private string $loggedInFailureCallback;
    private string $loggedOutFailureCallback;

    /**
     * Creates an object
     *
     * @param string $loggedInFailureCallback
     * @param string $loggedOutFailureCallback
     */
    public function __construct(string $loggedInFailureCallback, string $loggedOutFailureCallback)
    {
        $this->loggedInFailureCallback = $loggedInFailureCallback;
        $this->loggedOutFailureCallback = $loggedOutFailureCallback;
    }

    /**
     * Performs an authorization task.
     *
     * @param  \SimpleXMLElement $xml
     * @param  string            $routeToAuthorize
     * @param  int|string|null   $userID
     * @param  UserRoles         $userAuthorizationRoles
     * @return Result
     */
    public function authorize(
        \SimpleXMLElement $xml,
        string $routeToAuthorize,
        int|string|null $userID,
        UserRoles $userAuthorizationRoles
    ): Result {
        $status = 0;
        $callbackURI = "";

        // check if user is authenticated
        $isUserGuest = $userID===null;

        // get user roles
        $userRoles = $userAuthorizationRoles->getRoles($userID);

        // get page roles
        $detector = new RolesDetector($xml, "routes", "route", "id", $routeToAuthorize);
        $pageRoles = $detector->getRoles();
        if (empty($pageRoles)) {
            $status = ResultStatus::NOT_FOUND;
            $callbackURI = ($isUserGuest ? $this->loggedOutFailureCallback : $this->loggedInFailureCallback);
        } else {
            // compare user roles to page roles
            $allowed = false;
            foreach ($pageRoles as $role) {
                if (in_array($role, $userRoles)) {
                    $allowed= true;
                    break;
                }
            }

            // now perform rights check
            if ($allowed) {
                $status = ResultStatus::OK;
            } elseif ($isUserGuest) {
                $status = ResultStatus::UNAUTHORIZED;
                $callbackURI = $this->loggedOutFailureCallback;
            } else {
                $status = ResultStatus::FORBIDDEN;
                $callbackURI = $this->loggedInFailureCallback;
            }
        }

        return new Result($status, $callbackURI);
    }
}
