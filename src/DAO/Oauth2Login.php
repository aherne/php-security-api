<?php

namespace Lucinda\WebSecurity\DAO;

use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;

/**
 * Defines blueprints for a DAO that reflects oauth2 authentication results to database.
 */
interface Oauth2Login
{
    /**
     * Logs in OAuth2 user into current application. Exchanges authenticated OAuth2 user information for a
     * local user ID.
     *
     * @param  UserInformation $userInformation Object encapsulating detected OAuth2 user information.
     * @param  string          $vendorName      Name of OAuth2 vendor user has logged in by
     * @return int|string|null Unique user identifier (typically an int)
     */
    public function login(UserInformation $userInformation, string $vendorName): int|string|null;
}
