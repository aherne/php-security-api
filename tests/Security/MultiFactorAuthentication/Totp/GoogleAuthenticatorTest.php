<?php

namespace Test\Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;

use Lucinda\UnitTest\Validator\Integers;
use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp\GoogleAuthenticator;

final class GoogleAuthenticatorTest
{
    public function generateSecret()
    {
        $secret = (new GoogleAuthenticator())->generateSecret(20);

        return (new Strings($secret))->assertSize(32);
    }

    public function getProvisioningURI()
    {
        $authenticator = new GoogleAuthenticator();
        $uri = $authenticator->getProvisioningURI("Example Inc", "person@example.com", "JBSWY3DPEHPK3PXP", 30, 6);

        return (new Strings($uri))->assertContains("otpauth://totp/Example%20Inc:person%40example.com");
    }

    public function verify()
    {
        $secret = "JBSWY3DPEHPK3PXP";
        $period = 30;
        $counter = intdiv(time(), $period);
        $code = $this->createCode($secret, $counter, 6);
        $matchedCounter = (new GoogleAuthenticator())->verify($secret, $code, $period, 6, 0);

        return (new Integers($matchedCounter))->assertEquals($counter);
    }

    private function createCode(string $secret, int $counter, int $digits): string
    {
        $key = $this->decodeBase32($secret);
        $counterBytes = pack("N2", 0, $counter);
        $hash = hash_hmac("sha1", $counterBytes, $key, true);
        $offset = ord($hash[19]) & 0x0f;
        $binary = unpack("N", substr($hash, $offset, 4))[1] & 0x7fffffff;

        return str_pad((string) ($binary % (10 ** $digits)), $digits, "0", STR_PAD_LEFT);
    }

    private function decodeBase32(string $value): string
    {
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        $bits = "";
        foreach (str_split($value) as $character) {
            $position = strpos($alphabet, $character);
            $bits .= str_pad(decbin($position), 5, "0", STR_PAD_LEFT);
        }

        $decoded = "";
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $decoded .= chr(bindec($byte));
            }
        }

        return $decoded;
    }
}
