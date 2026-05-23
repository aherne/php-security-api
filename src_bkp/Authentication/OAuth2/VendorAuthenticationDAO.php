<?php

namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Defines blueprints for a DAO that reflects oauth2 authentication results to database.
 */
interface VendorAuthenticationDAO
{
    /**
     * Logs in OAuth2 user into current application. Exchanges authenticated OAuth2 user information for a
     * local user ID.
     *
     * @param  UserInformation $userInformation Object encapsulating detected OAuth2 user information.
     * @param  string          $vendorName      Name of OAuth2 vendor user has logged in by
     * @param  string          $accessToken     Access token to be saved in further requests for above user.
     * @return int|string|null Unique user identifier (typically an int)
     */
    public function login(UserInformation $userInformation, string $vendorName, string $accessToken): int|string|null;

    /**
     * Logs out local user and removes saved access token
     *
     * @param int|string $userID Unique user identifier (typically an int)
     */
    public function logout(int|string $userID): void;
}
