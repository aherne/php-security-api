<?php

namespace Lucinda\WebSecurity\Security\Authorization;

use Lucinda\WebSecurity\Configuration\Authorization\ByXML as Configuration;
use Lucinda\WebSecurity\Configuration\RolesDetector;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\ByXML\Authorization;

/**
 * Binds configured user-role lookup to pre-parsed route-role policies
 *
 * Construction creates the user-roles DAO and evaluates access to the
 * requested route through the roles detector. The computed decision is
 * available through getResult(); this class does not parse XML directly.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authorization\ByXML
 * @see \Lucinda\WebSecurity\Configuration\RolesDetector
 * @see \Lucinda\WebSecurity\DAO\UserRoles
 * @see \Lucinda\WebSecurity\Security\Authorization\ByXML\Authorization
 */
final class ByXML extends Generic
{
    /**
     * Constructs the user-roles DAO and executes the route-role access check
     *
     * @param Configuration $configuration Parsed roles DAO class and failure callbacks
     * @param Request $request Request supplying the route to authorize
     * @param int|string|null $userID Authenticated local user ID, or null for a guest
     * @param RolesDetector $rolesDetector Pre-parsed access roles indexed by route
     * @throws \Throwable If construction or evaluation of the user-roles DAO fails
     */
    public function __construct(Configuration $configuration, Request $request, int|string|null $userID, RolesDetector $rolesDetector)
    {
        $daoClass = $configuration->getRolesDAO();
        $rolesDAO = new $daoClass();

        // authorize and save result
        $authorization = new Authorization($configuration->getCallbackLoggedIn(), $configuration->getCallbackLoggedOut());
        $this->setResult($authorization->authorize($rolesDetector, $request->getUri(), $userID, $rolesDAO));
    }
}