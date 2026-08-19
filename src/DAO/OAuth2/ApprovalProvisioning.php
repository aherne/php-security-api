<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

use Lucinda\WebSecurity\OAuth2ApprovalStatus;

interface ApprovalProvisioning extends Login
{
    /**
     * Idempotently creates or finds an approval request.
     */
    public function requestApproval(
        UserInformation $userInformation,
        string $vendorName
    ): OAuth2ApprovalStatus;
}