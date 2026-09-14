<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines the DAO contract for username/password authentication
 *
 * Register the implementation class through the 'dao' attribute
 * of security > authentication > form.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Form
 */
interface FormLogin
{
    /**
     * Validates submitted credentials against a local account
     *
     * @param string $username Submitted username
     * @param string $password Submitted password
     * @return int|string|null Non-empty local user ID on success; null when authentication is rejected
     */
    public function login(string $username, string $password): int|string|null;
}
