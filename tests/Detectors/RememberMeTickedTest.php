<?php
namespace Test\Lucinda\WebSecurity\Detectors;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration;
use Lucinda\WebSecurity\Detectors\RememberMeTicked;
use Lucinda\WebSecurity\Request;

class RememberMeTickedTest
{
    private function configuration(): Configuration
    {
        return new Configuration(simplexml_load_string('
            <xml><security>
                <csrf secret="abcdefghijklmnopqrstuvwxyz123456"/>
                <persistence><session/></persistence>
                <authentication>
                    <form dao="Test\Lucinda\WebSecurity\mocks\Authentication\MockUsersAuthentication">
                        <login page="login" target_success="home" target_failure="retry" parameter_remember_me="stay"/>
                        <logout page="logout" target_success="bye" target_failure="error"/>
                    </form>
                </authentication>
                <authorization>
                    <by_dao page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO"
                        user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"
                        logged_in_callback="forbidden" logged_out_callback="login"/>
                </authorization>
            </security></xml>
        '));
    }

    public function getTicked(): array
    {
        $request = new Request();
        $request->setMethod("POST");
        $request->setParameters(["stay" => "1"]);
        $selected = new RememberMeTicked($this->configuration(), $request);

        $request->setMethod("GET");
        $notSelected = new RememberMeTicked($this->configuration(), $request);

        return [
            (new Booleans($selected->getTicked()))->assertTrue(),
            (new Booleans($notSelected->getTicked()))->assertFalse()
        ];
    }
}
