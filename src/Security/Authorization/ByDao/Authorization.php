<?php

namespace Lucinda\WebSecurity\Security\Authorization\ByDao;

use Lucinda\WebSecurity\DAO\PageAuthorization;
use Lucinda\WebSecurity\DAO\UserAuthorization;
use Lucinda\WebSecurity\Security\Authorization\Result;
use Lucinda\WebSecurity\Security\Authorization\ResultStatus;

/**
 * Encapsulates request authorization via DAOs.
 */
final class Authorization
{
    private string $loggedInFailureCallback;
    private string $loggedOutFailureCallback;

    /**
     * Creates an object
     *
     * @param string $loggedInFailureCallback  Callback page to use when authorization fails for logged in users.
     * @param string $loggedOutFailureCallback Callback page to use when authorization fails for logged out (guest) users.
     */
    public function __construct(string $loggedInFailureCallback, string $loggedOutFailureCallback)
    {
        $this->loggedInFailureCallback = $loggedInFailureCallback;
        $this->loggedOutFailureCallback = $loggedOutFailureCallback;
    }

    /**
     * Performs an authorization task
     *
     * @param  PageAuthorization $page
     * @param  UserAuthorization $user
     * @param  string               $httpRequestMethod
     * @return Result
     */
    public function authorize(PageAuthorization $page, UserAuthorization $user, string $httpRequestMethod): Result
    {
        $callbackURI = "";
        if ($page->getID()) {
            if (!$page->isPublic()) {
                if ($user->getID()!==null) {
                    if (!$user->isAllowed($page, $httpRequestMethod)) {
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
            if ($user->getID()!==null) {
                $callbackURI = $this->loggedInFailureCallback;
            } else {
                $callbackURI = $this->loggedOutFailureCallback;
            }
            $status = ResultStatus::NOT_FOUND;
        }
        return new Result($status, $callbackURI);
    }
}
