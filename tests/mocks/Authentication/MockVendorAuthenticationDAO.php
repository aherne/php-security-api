<?php

namespace Test\Lucinda\WebSecurity\mocks\Authentication;

use Lucinda\WebSecurity\DAO\Oauth2\UserInformation;
use Lucinda\WebSecurity\DAO\Oauth2Authentication;
use Lucinda\WebSecurity\DAO\UserRoles;

class MockVendorAuthenticationDAO implements Oauth2Authentication, UserRoles
{
    private $accounts = [];

    public function login(UserInformation $userInformation, string $vendorName, string $accessToken): int|string|null
    {
        if ($vendorName!="Facebook") {
            return null;
        }
        $this->accounts[1][$vendorName] = [
            "info"=>$userInformation,
            "access_token"=>$accessToken
        ];
        return 1;
    }

    public function logout(int|string $userID): bool
    {
        if (isset($this->accounts[$userID])) {
            foreach ($this->accounts[$userID] as $vendorName=>$info) {
                $this->accounts[$userID][$vendorName]["access_token"] = "";
            }
        }
        return true;
    }

    public function getRoles(int|string|null $userID): array
    {
        if ($userID) {
            return ["USER"];
        } else {
            return ["GUEST"];
        }
    }
}
