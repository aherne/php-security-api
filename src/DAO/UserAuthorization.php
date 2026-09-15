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
interface UserAuthorization
{
    /**
     * Checks whether this user may access the requested page using the HTTP method
     *
     * The authorization workflow calls this for an authenticated user accessing a non-public page.
     *
     * @param int|string $userID Non-empty local user ID, or null for a guest
     * @param int $pageID ID of the respective page already detected
     * @param string $httpRequestMethod Current HTTP request method, such as GET or POST
     * @return bool True when access is allowed; false when access is denied
     */
     public function isAllowed(int|string $userID, int $pageID, string $httpRequestMethod): bool;
}
