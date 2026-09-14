<?php

namespace Lucinda\WebSecurity\Security\Authorization\ByXML;

use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;
use Lucinda\WebSecurity\DAO\UserRoles;

/**
 * Compares user roles with the access roles declared for a requested route
 *
 * Uses a preconfigured roles detector rather than parsing XML. Access is
 * allowed when at least one route role matches a user role. Missing or empty
 * route-role policies produce NOT_FOUND; other denials distinguish guests
 * from authenticated users. Returns a decision without performing a redirect.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Security\Authorization\ByXML
 * @see RolesDetector
 * @see UserRoles
 */
final class Authorization
{
    private string $loggedInFailureCallback;
    private string $loggedOutFailureCallback;

    /**
     * Stores callbacks for denied access without evaluating a request
     *
     * @param string $loggedInFailureCallback Failure route for authenticated users
     * @param string $loggedOutFailureCallback Failure route for guests
     */
    public function __construct(string $loggedInFailureCallback, string $loggedOutFailureCallback)
    {
        $this->loggedInFailureCallback = $loggedInFailureCallback;
        $this->loggedOutFailureCallback = $loggedOutFailureCallback;
    }

    /**
     * Evaluates access by comparing the route's roles with the user's roles
     *
     * The user-roles DAO receives null for a guest. Matching any configured
     * route role grants access; a missing policy is not treated as public access.
     *
     * @param RolesDetector $rolesDetector Pre-parsed access roles indexed by route
     * @param string $routeToAuthorize Requested route identifier
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @param UserRoles $userAuthorizationRoles DAO returning roles for the current user or guest
     * @return Result Access decision with a failure callback, or an empty callback when access is allowed
     * @throws \Throwable If the user-roles DAO fails
     */
    public function authorize(
        RolesDetector $rolesDetector,
        string $routeToAuthorize,
        int|string|null $userID,
        UserRoles $userAuthorizationRoles
    ): Result {
        $status = 0;
        $callbackURI = "";

        // check if user is authenticated
        $isUserGuest = empty($userID);

        // get user roles
        $userRoles = $userAuthorizationRoles->getRoles($isUserGuest ? null : $userID);

        // get page roles
        $pageRoles = $rolesDetector->getRoles($routeToAuthorize);
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
