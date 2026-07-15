<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\Oauth2Service;
use Lucinda\WebSecurity\DAO\Oauth2\UserInformation;

class MockOauth2Driver implements Oauth2Service
{
    private $vendorName;

    public function __construct(string $vendorName)
    {
        $this->vendorName = $vendorName;
    }


    public function getUserInfo(string $accessToken): UserInformation
    {
        return new MockUserInformation(["id"=>123456, "name"=>"John Doe", "email"=>"john@doe.com"]);
    }

    public function getAuthorizationCodeEndpoint(): string
    {
        return "qwerty";
    }

    public function getAccessToken(string $authorizationCode): string
    {
        return "asdfgh";
    }

}
