<?php

namespace Test\Lucinda\WebSecurity\mocks\OAuth2;

use Lucinda\WebSecurity\DAO\OAuth2\ApprovalProvisioning;
use Lucinda\WebSecurity\DAO\OAuth2\UserInformation;
use Lucinda\WebSecurity\OAuth2ApprovalStatus;

final class ApprovalDAO implements ApprovalProvisioning
{
    public static int|string|null $resolved = null;
    public static OAuth2ApprovalStatus $approval = OAuth2ApprovalStatus::PENDING;

    public function resolve(UserInformation $userInformation, string $vendorName): int|string|null
    {
        return self::$resolved;
    }

    public function requestApproval(UserInformation $userInformation, string $vendorName): OAuth2ApprovalStatus
    {
        return self::$approval;
    }
}
