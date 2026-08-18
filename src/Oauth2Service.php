<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;

/**
 * Defines OAuth2Service contract.
 */
interface Oauth2Service
{
    function getAuthorizationCodeEndpoint(string $state): string;
    function getAccessToken(string $authorizationCode): string;
    function getUserInfo(string $accessToken): UserInformation;
    // TODO: migrate below to OAuth2State interface
    function produceState(string $state): void;
    function consumeState(): ?string;
}
