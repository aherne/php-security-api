<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines the DAO contract for retrieving user roles used in route authorization
 *
 * Register the implementation class through the 'roles_dao' attribute
 * of security > authorization > by_route.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authorization\ByXML
 */
interface UserRoles
{
    /**
     * Gets roles for a local user, or guest roles when no user is authenticated
     *
     * @param int|string|null $userID Non-empty local user ID, or null for a guest
     * @return string[] Role names to compare against the configured route roles; empty when none apply
     */
    function getRoles(int|string|null $userID): array;
}
