<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines blueprints for a DAO that checks logged in user's access levels in database.
 */
abstract class UserAuthorization
{
    protected int|string|null $userID;

    /**
     * UserAuthorizationDAO constructor.
     *
     * @param int|string|null $userID Unique user identifier
     */
    public function __construct(int|string|null $userID)
    {
        $this->userID = $userID;
    }

    /**
     * Checks if current user is allowed to access a page.
     *
     * @param  PageAuthorization $page
     * @param  string               $httpRequestMethod Current HTTP request method
     * @return boolean
     */
    abstract public function isAllowed(PageAuthorization $page, string $httpRequestMethod): bool;

    /**
     * Gets saved id of logged in user
     *
     * @return int|string|null
     */
    public function getID(): int|string|null
    {
        return $this->userID;
    }
}
