<?php

namespace Lucinda\WebSecurity;

use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Packets\MultiFactor as MultiFactorPacket;

/**
 * Defines OAuth2Service contract.
 */
interface Oauth2Service
{
    function getAuthorizationCodeEndpoint(): string;
    function getAccessToken(string $authorizationCode): string;
    function getUserInfo(string $accessToken): UserInformation;
}
