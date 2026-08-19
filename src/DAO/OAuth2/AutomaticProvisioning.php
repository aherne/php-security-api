<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

interface AutomaticProvisioning extends Login
{
    /**
     * Creates an eligible account and returns its local ID.
     * Returns null when registration is rejected.
     */
    public function create(
        UserInformation $userInformation,
        string $vendorName
    ): int|string|null;
}