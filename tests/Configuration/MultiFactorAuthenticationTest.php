<?php
namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Objects;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication;
use Test\Lucinda\WebSecurity\mocks\Authentication\MockMultiFactorAuthentication;

class MultiFactorAuthenticationTest
{
    private function subject(): MultiFactorAuthentication
    {
        return new MultiFactorAuthentication(simplexml_load_string('<xml><multi_factor_authentication dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockMultiFactorAuthentication" challenge_route="challenge" setup_route="setup" success_route="home" failure_route="retry" throttled_route="wait"><totp issuer="App"/></multi_factor_authentication></xml>'));
    }

    public function getDAO()
    {
        return (new Strings($this->subject()->getDAO()))->assertEquals(MockMultiFactorAuthentication::class);
    }

    public function getChallengeRoute()
    {
        return (new Strings($this->subject()->getChallengeRoute()))->assertEquals("challenge");
    }

    public function getSetupRoute()
    {
        return (new Strings($this->subject()->getSetupRoute()))->assertEquals("setup");
    }

    public function getSuccessRoute()
    {
        return (new Strings($this->subject()->getSuccessRoute()))->assertEquals("home");
    }

    public function getFailureRoute()
    {
        return (new Strings($this->subject()->getFailureRoute()))->assertEquals("retry");
    }

    public function getThrottledRoute()
    {
        return (new Strings($this->subject()->getThrottledRoute()))->assertEquals("wait");
    }

    public function getMethod()
    {
        return (new Objects($this->subject()->getMethod()))->assertInstanceOf(MultiFactorAuthentication\Totp::class);
    }
    public function getThrottler()
    {
    }
        

}
