<?php
namespace Test\Lucinda\WebSecurity\Security;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as MultiFactorConfiguration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;

class MultiFactorAuthenticationTest
{
    public function getOutcome(): array
    {
        $configuration = new MultiFactorConfiguration(simplexml_load_string(
            '<xml><multi_factor_authentication
                dao="Test\\Lucinda\\WebSecurity\\mocks\\Authentication\\MockMultiFactorAuthentication"
                challenge_route="challenge" setup_route="setup" success_route="home"
                failure_route="retry" throttled_route="wait">
                <totp issuer="App"/>
            </multi_factor_authentication></xml>'
        ));
        $request = new Request();
        $request->setUri("home");
        $request->setContextPath("");
        $request->setParameters([]);

        $guest = new MultiFactorAuthentication($configuration, $request, null);
        $user = new MultiFactorAuthentication($configuration, $request, 1);

        return [
            (new Booleans($guest->getOutcome() === null))->assertTrue(),
            (new Booleans($user->getOutcome()->getStatus() === ResultStatus::SETUP_REQUIRED))->assertTrue()
        ];
    }
}

