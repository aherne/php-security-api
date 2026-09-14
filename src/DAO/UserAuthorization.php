<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines the DAO base class for checking a local user's page permissions
 *
 * Register the concrete subclass through the 'user_dao' attribute
 * of security > authorization > by_dao.
 * The library constructs it with the current local user ID, or null for a guest.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authorization\ByDAO
 */
abstract class UserAuthorization
{
    protected int|string|null $userID;

    /**
     * Stores the local user ID used for subsequent authorization checks
     *
     * @param int|string|null $userID Non-empty local user ID, or null for a guest
     */
    public function __construct(int|string|null $userID)
    {
        $this->userID = $userID;
    }

    /**
     * Checks whether this user may access the requested page using the HTTP method
     *
     * The authorization workflow calls this for an authenticated user accessing a non-public page.
     *
     * @param PageAuthorization $page Resolved page whose permissions are checked
     * @param string $httpRequestMethod Current HTTP request method, such as GET or POST
     * @return bool True when access is allowed; false when access is denied
     */
    abstract public function isAllowed(PageAuthorization $page, string $httpRequestMethod): bool;

    /**
     * Gets the stored local user ID
     *
     * @return int|string|null Local user ID, or null for a guest
     */
    public function getID(): int|string|null
    {
        return $this->userID;
    }
}
