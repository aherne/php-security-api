<?php
namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\Authentication;

class AuthenticationTest
{

    public function getMethods()
    {
        $object = new Authentication(\simplexml_load_string('
        <security>
                <authentication>
                    <form dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication">
                        <login page="login" target_success="index" target_failure="login_failed"/>
                        <logout page="logout" target_success="login" target_failure="logout_failed"/>
                    </form>
                </authentication>
        </security>
        '));
        return (new Arrays($object->getMethods()))->assertNotEmpty();
    }
        

    public function getLoginMethods()
    {
    }
        

    public function getLogoutMethod()
    {
    }
        

}
