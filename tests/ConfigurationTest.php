<?php
namespace Test\Lucinda\WebSecurity;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration;

class ConfigurationTest
{
    private string $secret;
    private Configuration $configuration;

    public function __construct()
    {
        $this->secret = str_repeat("a", 32);
        $this->configuration = new Configuration(simplexml_load_string('
            <xml>
            <security>
                <csrf secret="'.$this->secret.'"/>
                <persistence><synchronizer_token secret="'.$this->secret.'"/></persistence>
                <authentication>
                    <form dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication">
                        <login page="login" target_success="index" target_failure="login_failed"/>
                        <logout page="logout" target_success="login" target_failure="logout_failed"/>
                    </form>
                </authentication>
                <authorization>
                    <by_dao
                        page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO"
                        user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"
                        logged_in_callback="forbidden"
                        logged_out_callback="login"/>
                </authorization>
                <multi_factor_authentication dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockMultiFactorAuthentication"
                 challenge_route="challenge" setup_route="setup" success_route="home" failure_route="retry" throttled_route="wait">
                    <totp issuer="App"/>
                </multi_factor_authentication>
            </security>
            </xml>
        '));
    }

    public function getPersistence()
    {
        return (new Arrays($this->configuration->getPersistence()->getDrivers()))->assertNotEmpty();
    }
        

    public function getCsrf()
    {
        return (new Strings($this->configuration->getCsrf()->getSecret()))->assertEquals($this->secret);
    }
        

    public function getAuthentication()
    {
        return (new Arrays($this->configuration->getAuthentication()->getMethods()))->assertNotEmpty();
    }
        

    public function getAuthorization()
    {
        return (new Arrays($this->configuration->getAuthorization()->getMethods()))->assertNotEmpty();
    }
        

    public function getMultiFactorAuthentication()
    {
        return (new Strings($this->configuration->getMultiFactorAuthentication()->getChallengeRoute()))->assertEquals("challenge");
    }
        

}
