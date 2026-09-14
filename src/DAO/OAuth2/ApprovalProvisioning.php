<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

use Lucinda\WebSecurity\OAuth2ApprovalStatus;

/**
 * Defines the DAO contract for recording OAuth2 account approval requests
 *
 * Register the implementation class through the 'dao' attribute
 * of security > authentication > oauth2 with provisioning="approval_required".
 *
 * @see \Lucinda\WebSecurity\Configuration\Authentication\Oauth2
 * @see Login::resolve()
 */
interface ApprovalProvisioning extends Login
{
    /**
     * Idempotently creates or finds an approval request for an OAuth2 identity
     *
     * Called only when resolve() returns null and approval provisioning is configured.
     * Repeated calls for the same provider identity must not create duplicate requests.
     * Once an approved local account is available, resolve() should return it on a later login.
     *
     * @param UserInformation $userInformation User information returned by the OAuth2 provider
     * @param string $vendorName Provider name configured in the oauth2 > driver 'name' attribute
     * @return OAuth2ApprovalStatus PENDING while approval is outstanding; REJECTED when access is denied
     */
    public function requestApproval(
        UserInformation $userInformation,
        string $vendorName
    ): OAuth2ApprovalStatus;
}