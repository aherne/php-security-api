<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;

/**
 * Encapsulates GoogleAuthenticator logic.
 */
final class GoogleAuthenticator
{
    private const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * Generate secret.
     *
     * @param int $length
     * @return string
     */
    public function generateSecret(int $length = 20): string
    {
        $bytes = random_bytes($length);
        $bits = "";
        foreach (str_split($bytes) as $byte) {
            $bits .= str_pad(decbin(ord($byte)), 8, "0", STR_PAD_LEFT);
        }

        $secret = "";
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, "0", STR_PAD_RIGHT);
            }
            $secret .= self::BASE32_ALPHABET[bindec($chunk)];
        }
        return $secret;
    }

    /**
     * Gets provisioning URI.
     *
     * @param string $issuer
     * @param string $accountName
     * @param string $secret
     * @param int $period
     * @param int $digits
     * @return string
     */
    public function getProvisioningURI(
        string $issuer,
        string $accountName,
        string $secret,
        int $period,
        int $digits
    ): string {
        $label = rawurlencode($issuer).":".rawurlencode($accountName);
        return "otpauth://totp/".$label."?" . http_build_query(
            [
                "secret" => $secret,
                "issuer" => $issuer,
                "algorithm" => "SHA1",
                "digits" => $digits,
                "period" => $period
            ],
            "",
            "&",
            PHP_QUERY_RFC3986
        );
    }

    /**
     * Verify.
     *
     * @param string $secret
     * @param string $code
     * @param int $period
     * @param int $digits
     * @param int $window
     * @return ?int Matched counter, or null when the code is invalid
     */
    public function verify(string $secret, string $code, int $period, int $digits, int $window): ?int
    {
        if (!preg_match('/^\d{'.$digits.'}$/', $code)) {
            return null;
        }

        $counter = intdiv(time(), $period);
        for ($i = -$window; $i <= $window; $i++) {
            $candidateCounter = $counter + $i;
            if (hash_equals($this->generateCode($secret, $candidateCounter, $digits), $code)) {
                return $candidateCounter;
            }
        }
        return null;
    }

    /**
     * Generate code.
     *
     * @param string $secret
     * @param int $counter
     * @param int $digits
     * @return string
     */
    private function generateCode(string $secret, int $counter, int $digits): string
    {
        $key = $this->decodeBase32($secret);
        $time = pack("N*", 0, $counter);
        $hash = hash_hmac("sha1", $time, $key, true);
        $offset = ord($hash[19]) & 0x0F;
        $value = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        );
        return str_pad((string) ($value % (10 ** $digits)), $digits, "0", STR_PAD_LEFT);
    }

    /**
     * Decode base32.
     *
     * @param string $secret
     * @return string
     */
    private function decodeBase32(string $secret): string
    {
        $secret = strtoupper($secret);
        $bits = "";
        foreach (str_split($secret) as $character) {
            $position = strpos(self::BASE32_ALPHABET, $character);
            if ($position === false) {
                continue;
            }
            $bits .= str_pad(decbin($position), 5, "0", STR_PAD_LEFT);
        }

        $output = "";
        foreach (str_split($bits, 8) as $chunk) {
            if (strlen($chunk) === 8) {
                $output .= chr(bindec($chunk));
            }
        }
        return $output;
    }
}
