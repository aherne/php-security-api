<?php
namespace Test\Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;

use Lucinda\UnitTest\Validator\Booleans;
use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp\GoogleAuthenticator;

class GoogleAuthenticatorTest
{
    private GoogleAuthenticator $authenticator;

    public function __construct()
    {
        $this->authenticator = new GoogleAuthenticator();
    }

    public function generateSecret(): array
    {
        $secret = $this->authenticator->generateSecret(20);
        return [
            (new Integers(strlen($secret)))->assertEquals(32),
            (new Booleans((bool) preg_match('/^[A-Z2-7]+$/', $secret)))->assertTrue()
        ];
    }

    public function getProvisioningURI()
    {
        $uri = $this->authenticator->getProvisioningURI("My App", "a+b@example.com", "ABC234", 30, 6);
        return (new Strings($uri))->assertEquals(
            "otpauth://totp/My%20App:a%2Bb%40example.com?secret=ABC234&issuer=My%20App&algorithm=SHA1&digits=6&period=30"
        );
    }

    public function verify(): array
    {
        $period = 300;
        $digits = 6;
        $counter = intdiv(time(), $period);
        $method = new \ReflectionMethod($this->authenticator, "generateCode");
        $code = $method->invoke($this->authenticator, "ABC234", $counter, $digits);

        return [
            (new Booleans($this->authenticator->verify("ABC234", "abc123", 30, 6, 1) === null))->assertTrue(),
            (new Booleans($this->authenticator->verify("ABC234", "12345", 30, 6, 1) === null))->assertTrue(),
            (new Integers($this->authenticator->verify("ABC234", $code, $period, $digits, 0) ?? -1))->assertEquals($counter)
        ];
    }
}
