<?php

namespace Test\Lucinda\WebSecurity;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\WebSecurity\Configuration\Authentication;
use Lucinda\WebSecurity\Configuration\Authorization;
use Lucinda\WebSecurity\Configuration\Csrf;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;
use Lucinda\WebSecurity\Configuration\Persistence;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class ConfigurationTest
{
    public function getPersistence()
    {
        $actual = Fixture::configuration()->getPersistence();

        return (new Objects($actual))->assertInstanceOf(Persistence::class);
    }

    public function getCsrf()
    {
        $actual = Fixture::configuration()->getCsrf();

        return (new Objects($actual))->assertInstanceOf(Csrf::class);
    }

    public function getAuthentication()
    {
        $actual = Fixture::configuration()->getAuthentication();

        return (new Objects($actual))->assertInstanceOf(Authentication::class);
    }

    public function getAuthorization()
    {
        $actual = Fixture::configuration()->getAuthorization();

        return (new Objects($actual))->assertInstanceOf(Authorization::class);
    }

    public function getMultiFactorAuthentication()
    {
        $actual = Fixture::configuration(true)->getMultiFactorAuthentication();

        return (new Objects($actual))->assertInstanceOf(MultiFactorAuthentication::class);
    }
}
