<?php

namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication\Totp;
use Test\Lucinda\WebSecurity\mocks\Authentication\MultiFactorAuthenticationDAO;
use Test\Lucinda\WebSecurity\mocks\Authentication\MultiFactorAuthenticationThrottler;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class MultiFactorAuthenticationTest
{
    private function configuration(): MultiFactorAuthentication
    {
        return Fixture::configuration(true)->getMultiFactorAuthentication();
    }

    public function getDAO()
    {
        $actual = $this->configuration()->getDAO();

        return (new Strings($actual))->assertEquals(MultiFactorAuthenticationDAO::class);
    }

    public function getThrottler()
    {
        $actual = $this->configuration()->getThrottler();

        return (new Strings($actual))->assertEquals(MultiFactorAuthenticationThrottler::class);
    }

    public function getExpiration()
    {
        $actual = $this->configuration()->getExpiration();

        return (new Integers($actual))->assertEquals(600);
    }

    public function getPendingExpiration()
    {
        $actual = $this->configuration()->getPendingExpiration();

        return (new Integers($actual))->assertEquals(120);
    }

    public function getChallengeRoute()
    {
        $actual = $this->configuration()->getChallengeRoute();

        return (new Strings($actual))->assertEquals("mfa/challenge");
    }

    public function getSetupRoute()
    {
        $actual = $this->configuration()->getSetupRoute();

        return (new Strings($actual))->assertEquals("mfa/setup");
    }

    public function getSuccessRoute()
    {
        $actual = $this->configuration()->getSuccessRoute();

        return (new Strings($actual))->assertEquals("mfa/success");
    }

    public function getFailureRoute()
    {
        $actual = $this->configuration()->getFailureRoute();

        return (new Strings($actual))->assertEquals("mfa/failure");
    }

    public function getThrottledRoute()
    {
        $actual = $this->configuration()->getThrottledRoute();

        return (new Strings($actual))->assertEquals("mfa/throttled");
    }

    public function getMethod()
    {
        $actual = $this->configuration()->getMethod();

        return (new Objects($actual))->assertInstanceOf(Totp::class);
    }
}
