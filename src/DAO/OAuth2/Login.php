<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

interface Login
{
    /**
     * Read-only lookup.
     */
    public function resolve(
        UserInformation $userInformation,
        string $vendorName
    ): int|string|null;
}