<?php

namespace Test\Lucinda\WebSecurity\Authorization\DAO;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authorization\DAO\Authorization;
use Lucinda\WebSecurity\Authorization\Result as AuthorizationResult;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO;
use Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO;

class AuthorizationTest
{
    public function authorize()
    {
        $authorization = new Authorization("login", "index");

        return [
            (new Strings($this->test($authorization, "asdf", null)->getStatus()->name))->assertEquals(ResultStatus::NOT_FOUND->name, "test path not found"),
            (new Strings($this->test($authorization, "login", null)->getStatus()->name))->assertEquals(ResultStatus::OK->name, "guest allowed to login"),
            (new Strings($this->test($authorization, "index", null)->getStatus()->name))->assertEquals(ResultStatus::UNAUTHORIZED->name, "guest unauthorized to index"),
            (new Strings($this->test($authorization, "index", 1)->getStatus()->name))->assertEquals(ResultStatus::OK->name, "user allowed to index"),
            (new Strings($this->test($authorization, "administration", 1)->getStatus()->name))->assertEquals(ResultStatus::FORBIDDEN->name, "user forbidden to administration"),
        ];
    }

    private function test(Authorization $authorization, string $url, ?int $userID): AuthorizationResult
    {
        return $authorization->authorize(new MockPageAuthorizationDAO($url), new MockUserAuthorizationDAO($userID), "GET");
    }
}
