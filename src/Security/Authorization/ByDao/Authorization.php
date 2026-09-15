<?php

namespace Lucinda\WebSecurity\Security\Authorization\ByDao;

use Lucinda\WebSecurity\DAO\PageAuthorization;
use Lucinda\WebSecurity\DAO\UserAuthorization;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

/**
 * Evaluates resource existence, public access, and user permission through DAOs
 *
 * Missing resources produce NOT_FOUND. Public resources are permitted;
 * other resources require an authenticated user and a positive permission
 * decision for the request's HTTP method. Returns a decision and callback
 * without performing a redirect.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Security\Authorization\ByDao
 * @see Result
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
     * Evaluates whether the current user may access the requested resource
     *
     * User-specific permission checks are skipped for public resources.
     * Missing resources and denied access select a callback based on whether
     * a non-empty user ID is available.
     *
     * @param string $pageURL Requested route supplied by Request::getUri()
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @param PageAuthorization $pageDAO DAO representing the requested resource and its public-access policy
     * @param UserAuthorization $user DAO representing the current user or guest and their permissions
     * @param string $httpRequestMethod HTTP method used for the user-specific permission check
     * @return Result Access decision with a failure callback, or an empty callback when access is allowed
     * @throws \Throwable If an authorization DAO fails
     */
    public function authorize(
        string $pageURL,
        int|string|null $userID,
        PageAuthorization $pageDAO,
        UserAuthorization $userDAO,
        string $httpRequestMethod
        ): Result
    {
        $callbackURI = "";
        if ($pageID = $pageDAO->getID($pageURL)) {
            if (!$pageDAO->isPublic($pageID)) {
                if (!empty($userID)) {
                    if (!$userDAO->isAllowed($userID, $pageID, $httpRequestMethod)) {
                        $callbackURI = $this->loggedInFailureCallback;
                        $status = ResultStatus::FORBIDDEN;
                    } else {
                        // ok: do nothing
                        $status = ResultStatus::OK;
                    }
                } else {
                    $callbackURI = $this->loggedOutFailureCallback;
                    $status = ResultStatus::UNAUTHORIZED;
                }
            } else {
                // do nothing: it is allowed by default to display public panels
                $status = ResultStatus::OK;
            }
        } else {
            if (!empty($userID)) {
                $callbackURI = $this->loggedInFailureCallback;
            } else {
                $callbackURI = $this->loggedOutFailureCallback;
            }
            $status = ResultStatus::NOT_FOUND;
        }
        return new Result($status, $callbackURI);
    }
}
