<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Detectors\CsrfToken;
use Lucinda\WebSecurity\Packets\LoggedInUser;
use Lucinda\WebSecurity\Wrapper;
use Test\Lucinda\WebSecurity\mocks\Authorization\PageAuthorizationDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class WrapperTest
{
    public function getOutcome()
    {
        PageAuthorizationDAO::$pageID = 10;
        PageAuthorizationDAO::$public = true;
        $guestWrapper = new Wrapper(Fixture::xml(), Fixture::request("forum"));
        $guestOutcome = $guestWrapper->getOutcome();

        $configuration = Fixture::configuration();
        $request = Fixture::request("login", "POST");
        $csrf = new CsrfToken($configuration->getCsrf(), $request->getIpAddress());
        $request->setParameters([
            "username" => "person@example.com",
            "password" => "correct-password",
            "csrf" => $csrf->generate("guest")
        ]);
        $loginWrapper = new Wrapper(Fixture::xml(), $request);
        $loginOutcome = $loginWrapper->getOutcome();

        return [
            (new Arrays([$guestOutcome]))->assertIdentical([null]),
            (new Objects($loginOutcome))->assertInstanceOf(LoggedInUser::class),
            (new Arrays([$loginOutcome->getUserID()]))->assertIdentical([7]),
            (new Strings($loginOutcome->getCsrfToken()))->assertNotEmpty(),
            (new Strings($loginOutcome->getAccessToken()))->assertNotEmpty()
        ];
    }
}
