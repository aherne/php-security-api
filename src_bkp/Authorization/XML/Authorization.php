<?php

namespace Lucinda\WebSecurity\Authorization\XML;

use Lucinda\WebSecurity\ConfigurationException;
use Lucinda\WebSecurity\Authorization\Result;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\WebSecurity\Authorization\UserRoles;

/**
 * Encapsulates request authorization via XML that must have routes configured as:
 * <routes>
 *     <route id="{PAGE_TO_AUTHORIZE" access="ROLE_GUEST|ROLE_USER" ... />
 *     ...
 * </routes>
 */
class Authorization
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
        $isUserGuest = !$userID;

        // get user roles
        $userRoles = $userAuthorizationRoles->getRoles($userID);

        // get page roles
        $pageDAO = new PageAuthorizationXML($xml);
        $pageRoles = $pageDAO->getRoles($routeToAuthorize);
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
