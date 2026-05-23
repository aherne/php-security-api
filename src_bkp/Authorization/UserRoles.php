<?php

namespace Lucinda\WebSecurity\Authorization;

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
    public function getRoles(int|string|null $userID): array;
}
