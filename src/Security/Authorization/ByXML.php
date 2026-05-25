<?php

namespace Lucinda\WebSecurity\Security\Authorization;

use Lucinda\WebSecurity\Configuration\Authorization\ByXML as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\ByXML\Authorization;

/**
 * Encapsulates ByXML logic.
 */
final class ByXML extends Generic
{
    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param int|string|null $userID
     * @param \SimpleXMLElement $routes
     */
    public function __construct(Configuration $configuration, Request $request, int|string|null $userID, \SimpleXMLElement $routes)
    {
        $daoClass = $configuration->getRolesDAO();
        $rolesDAO = new $daoClass();

        // authorize and save result
        $authorization = new Authorization($configuration->getCallbackLoggedIn(), $configuration->getCallbackLoggedOut());
        $this->setResult($authorization->authorize($routes, $request->getUri(), $userID, $rolesDAO));
    }
}