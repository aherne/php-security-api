<?php

namespace Lucinda\WebSecurity\Authentication\DAO;

/**
 * Defines blueprints for a DAO that forwards user-password authentication to database.
 */
interface UserAuthenticationDAO
{
    /**
     * Performs a login operation in DB
     *
     * @param  string $username Value of user name
     * @param  string $password Value of user password
     * @return int|string|null Unique user identifier (typically an int)
     */
    public function login(string $username, string $password): int|string|null;

    /**
     * Performs a logout operation in DB
     *
     * @param int|string $userID Unique user identifier (typically an int)
     */
    public function logout(int|string $userID): void;
}
