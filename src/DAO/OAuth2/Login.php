<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

/**
 * Defines the DAO contract for resolving an OAuth2 identity to an existing local account
 *
 * Register the implementation class through the 'dao' attribute
 * of security > authentication > oauth2 with provisioning="existing_only".
 * Automatic and approval provisioning DAOs extend this same lookup contract.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Oauth2
 */
interface Login
{
    /**
     * Looks up an existing local account for the supplied provider identity
     *
     * This operation is read-only and must not create or modify accounts.
     * The provider name and remote user ID together identify the remote account.
     * Return only an account eligible to log in; pending or rejected requests must not resolve.
     *
     * @param UserInformation $userInformation User information returned by the OAuth2 provider
     * @param string $vendorName Provider name configured in the oauth2 > driver 'name' attribute
     * @return int|string|null Non-empty local user ID when eligible; null when no eligible account is found
     */
    public function resolve(
        UserInformation $userInformation,
        string $vendorName
    ): int|string|null;
}