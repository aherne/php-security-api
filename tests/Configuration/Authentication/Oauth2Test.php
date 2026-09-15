<?php

namespace Test\Lucinda\WebSecurity\Configuration\Authentication;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2;
use Lucinda\WebSecurity\Configuration\Authentication\Oauth2\Provisioning;
use Test\Lucinda\WebSecurity\mocks\OAuth2\ApprovalDAO;
use Test\Lucinda\WebSecurity\Support\Fixture;

final class Oauth2Test
{
    private function configuration(): Oauth2
    {
        return new Oauth2(Fixture::node("oauth-approval"));
    }

    public function getProvisioning()
    {
        $actual = $this->configuration()->getProvisioning();

        return (new Arrays([$actual]))->assertIdentical([Provisioning::APPROVAL_REQUIRED]);
    }

    public function getDAO()
    {
        $actual = $this->configuration()->getDAO();

        return (new Strings($actual))->assertEquals(ApprovalDAO::class);
    }

    public function getDrivers()
    {
        $actual = $this->configuration()->getDrivers();

        return (new Arrays($actual))->assertSize(1);
    }

    public function getTargetPending()
    {
        $actual = $this->configuration()->getTargetPending();

        return (new Strings($actual))->assertEquals("pending");
    }

    public function getStateExpiration()
    {
        $actual = $this->configuration()->getStateExpiration();

        return (new Integers($actual))->assertEquals(300);
    }

    public function getTargetSuccess()
    {
        $actual = $this->configuration()->getTargetSuccess();

        return (new Strings($actual))->assertEquals("home");
    }

    public function getTargetFailure()
    {
        $actual = $this->configuration()->getTargetFailure();

        return (new Strings($actual))->assertEquals("denied");
    }
}
