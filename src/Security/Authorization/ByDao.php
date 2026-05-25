<?php

namespace Lucinda\WebSecurity\Security\Authorization;

use Lucinda\WebSecurity\Configuration\Authorization\ByDAO as Configuration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\Authorization\ByDao\Authorization;

/**
 * Encapsulates ByDao logic.
 */
final class ByDao extends Generic
{
    /**
     * Sets up object state.
     *
     * @param Configuration $configuration
     * @param Request $request
     * @param int|string|null $userID
     */
    public function __construct(Configuration $configuration, Request $request, int|string|null $userID)
    {
        $daoClass = $configuration->getUserDAO();
        $userDAO = new $daoClass($userID);

        $daoClass = $configuration->getPageDAO();
        $pageDAO = new $daoClass($request->getUri());

        $authorization = new Authorization($configuration->getCallbackLoggedIn(), $configuration->getCallbackLoggedOut());
        $this->setResult($authorization->authorize($pageDAO, $userDAO, $request->getMethod()));
    }
}