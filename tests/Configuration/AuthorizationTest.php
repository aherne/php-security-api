<?php
namespace Test\Lucinda\WebSecurity\Configuration;

use Lucinda\UnitTest\Validator\Arrays;
use Lucinda\WebSecurity\Configuration\Authorization;

class AuthorizationTest
{

    public function getMethods()
    {
        $object = new Authorization(\simplexml_load_string('
        <security>
                <authorization>
                    <by_dao
                        page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO"
                        user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"
                        logged_in_callback="forbidden"
                        logged_out_callback="login"/>
                </authorization>
        </security>
        '));
        return (new Arrays($object->getMethods()))->assertNotEmpty();
    }
        

}
