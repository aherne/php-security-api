<?php
namespace Test\Lucinda\WebSecurity\Security\MultiFactorAuthentication;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Configuration\MultiFactorAuthentication as MultiFactorConfiguration;
use Lucinda\WebSecurity\Request;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\ResultStatus;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;

class TotpTest
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
        $authentication = new Totp($configuration, $request, 1);
        $outcome = $authentication->getOutcome();

        return [
            (new Booleans($outcome->getStatus() === ResultStatus::SETUP_REQUIRED))->assertTrue(),
            (new Strings($outcome->getSecret() ?? ""))->assertNotEmpty(),
            (new Strings($outcome->getProvisioningURI() ?? ""))->assertNotEmpty()
        ];
    }
}

