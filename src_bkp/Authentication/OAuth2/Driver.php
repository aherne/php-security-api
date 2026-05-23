<?php

namespace Lucinda\WebSecurity\Authentication\OAuth2;

/**
 * Defines driver to abstract OAuth2 operations required by Security API.
 */
interface Driver
{
    /**
     * Gets remote user information from oauth2 driver via access token.
     *
     * @param  string $accessToken OAuth2 access token
     * @return UserInformation Remote user information
     */
    public function getUserInformation(string $accessToken): UserInformation;

    /**
     * Gets login page relevant to current provider
     *
     * @return string
     */
    public function getCallbackUrl(): string;

    /**
     * Produces an authorization code request URL for current provider
     *
     * @param  string $state
     * @return string
     */
    public function getAuthorizationCode(string $state): string;

    /**
     * Asks remote provider to exchange authorization code with an access token
     *
     * @param  string $authorizationCode
     * @return string
     */
    public function getAccessToken(string $authorizationCode): string;

    /**
     * Gets name of OAuth2 vendor
     *
     * @return string
     */
    public function getVendorName(): string;
}
