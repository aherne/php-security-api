<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

/**
 * Defines the DAO contract for automatic creation of local accounts through OAuth2
 *
 * Register the implementation class through the 'dao' attribute
 * of security > authentication > oauth2 with provisioning="automatic".
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Oauth2
 * @see Login::resolve()
 */
interface AutomaticProvisioning extends Login
{
    /**
     * Creates an eligible local account for an OAuth2 identity and returns its ID
     *
     * Called only when resolve() returns null and automatic provisioning is configured.
     * The implementation decides whether the identity is eligible for account creation.
     *
     * @param UserInformation $userInformation User information returned by the OAuth2 provider
     * @param string $vendorName Provider name configured in the oauth2 > driver 'name' attribute
     * @return int|string|null Non-empty local user ID on success; null when registration is rejected
     */
    public function create(
        UserInformation $userInformation,
        string $vendorName
    ): int|string|null;
}