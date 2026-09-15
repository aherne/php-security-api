<?php

namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Detectors\RememberMeTicked;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class RememberMeTickedTest
{
    public function getTicked()
    {
        $request = Fixture::request("login", "POST", ["remember_me" => "1"]);
        $detector = new RememberMeTicked(Fixture::configuration(), $request);

        return (new Booleans($detector->getTicked()))->assertTrue();
    }
}
