<?php

namespace Lucinda\WebSecurity\Security\Authorization;

use Lucinda\WebSecurity\Configuration\Authorization\ByDAO as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\ByDao\Authorization;

/**
 * Builds the configured page and user DAOs and evaluates resource access
 *
 * Construction passes the requested route, current user identity, and HTTP
 * method to DAO-based authorization. The computed decision is available
 * through getResult(); this class does not produce a security packet.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authorization\ByDAO
 * @see \Lucinda\WebSecurity\DAO\PageAuthorization
 * @see \Lucinda\WebSecurity\DAO\UserAuthorization
 * @see \Lucinda\WebSecurity\Security\Authorization\ByDao\Authorization
 */
final class ByDao extends Generic
{
    /**
     * Constructs the configured DAOs and executes the access check
     *
     * @param Configuration $configuration Parsed page/user DAO classes and failure callbacks
     * @param Request $request Request supplying the resource route and HTTP method
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @throws \Throwable If construction or evaluation of an authorization DAO fails
     */
    public function __construct(Configuration $configuration, Request $request, int|string|null $userID)
    {
        $daoClass = $configuration->getUserDAO();
        $userDAO = new $daoClass();

        $daoClass = $configuration->getPageDAO();
        $pageDAO = new $daoClass();

        $authorization = new Authorization($configuration->getCallbackLoggedIn(), $configuration->getCallbackLoggedOut());
        $this->setResult($authorization->authorize(
            $request->getUri(),
            $userID,
            $pageDAO,
            $userDAO,
            $request->getMethod()
            ));
    }
}