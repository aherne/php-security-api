<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines blueprints for user roles getting.
 */
interface UserRoles
{
    /**
     * Gets user roles
     *
     * @param  int|string|null $userID
     * @return string[]
     */
    function getRoles(int|string|null $userID): array;
}
