<?php

namespace Lucinda\WebSecurity\DAO;

interface Logout
{

    /**
     * Performs a logout operation in DB
     *
     * @param int|string $userID Unique user identifier (typically an int)
     * @return bool If logout was successful
     */
    public function logout(int|string $userID): bool;
}