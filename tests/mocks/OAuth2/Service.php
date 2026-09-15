<?php

namespace Test\Lucinda\WebSecurity\mocks\OAuth2;

use Lucinda\WebSecurity\OAuth2Service;

final class Service implements OAuth2Service
{
    public ?string $receivedState = null;

    public function getAuthorizationCodeEndpoint(string $state): string
    {
        $this->receivedState = $state;

        return "https://provider.example/authorize?state=".$state;
    }

    public function getAccessToken(string $authorizationCode): string
    {
        return "provider-token";
    }

    public function getUserInfo(string $accessToken): \Lucinda\WebSecurity\DAO\OAuth2\UserInformation
    {
        return new UserInformation();
    }
}
