<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines the DAO contract for database operations performed during logout
 *
 * Register the implementation class through the 'dao' attribute
 * of security > authentication > logout.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Logout
 */
interface Logout
{

    /**
     * Performs the application's database logout operation for the user
     *
     * @param int|string $userID Non-empty local user ID
     * @return bool True when the operation succeeds; false when logout is rejected
     */
    public function logout(int|string $userID): bool;
}