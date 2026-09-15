<?php

namespace Test\Lucinda\WebSecurity\mocks\OAuth2;

final class UserInformation implements \Lucinda\WebSecurity\DAO\OAuth2\UserInformation
{
    public function getId(): int|string
    {
        return "remote-7";
    }

    public function getName(): string
    {
        return "Test User";
    }

    public function getEmail(): string
    {
        return "test@example.com";
    }
}
