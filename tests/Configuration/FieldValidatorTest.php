<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Provisioning;
use Lucinda\WebSecurity\Configuration\FieldValidator;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class FieldValidatorTest
{
    public function getValidInteger()
    {
        $xml = Fixture::node("valid-integer");
        $actual = (new FieldValidator())->getValidInteger($xml, "count", 1);

        return (new Integers($actual))->assertEquals(12);
    }

    public function getValidBoolean()
    {
        $xml = Fixture::node("valid-boolean");
        $actual = (new FieldValidator())->getValidBoolean($xml, "enabled");

        return (new Booleans($actual))->assertTrue();
    }

    public function getValidEnum()
    {
        $xml = Fixture::node("valid-enum");
        $actual = (new FieldValidator())->getValidEnum($xml, "policy", Provisioning::class);

        return (new Arrays([$actual]))->assertIdentical([Provisioning::AUTOMATIC]);
    }
}
