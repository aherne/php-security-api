<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp;

/**
 * Provides local TOTP secret generation, provisioning URIs, and code matching
 *
 * Uses Base32 secrets and SHA-1 TOTP codes. Verification returns a matched
 * time-step counter; it neither consumes that counter nor stores enrollment
 * state. The enclosing TOTP workflow delegates replay prevention to its DAO.
 * This helper does not communicate with a Google service.
 *
 * @internal
 * @see \Lucinda\WebSecurity\Security\MultiFactorAuthentication\Totp
 */
final class GoogleAuthenticator
{
    /**
     * Alphabet used to encode random secret bytes and decode Base32 TOTP secrets
     */
    private const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /**
     * Generates random bytes and encodes them as an unpadded Base32 secret
     *
     * The length describes random bytes, not the number of Base32 characters.
     * The resulting secret is sensitive and must be excluded from logs.
     *
     * @param int $length Number of random bytes to generate; must be positive
     * @return string Uppercase, unpadded Base32 secret
     * @throws \ValueError If the requested byte length is less than one
     * @throws \Exception If secure random bytes cannot be generated
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
     * Builds an otpauth URI for enrolling the secret in an authenticator app
     *
     * The URI includes the secret and must be treated as sensitive credential
     * material. Produces the URI only; it does not generate a QR-code image.
     *
     * @param string $issuer Application or organization label shown by the authenticator
     * @param string $accountName User-facing account label, such as a username or email address
     * @param string $secret Base32-encoded enrollment secret
     * @param int $period Duration of each TOTP time step in seconds
     * @param int $digits Number of decimal digits in generated codes
     * @return string URL-encoded otpauth enrollment URI specifying the SHA1 algorithm
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
     * Finds the time-step counter matching the submitted TOTP code
     *
     * Rejects incorrectly formatted codes, then checks the configured time window
     * from earliest to latest. Does not check whether a matching counter was
     * previously used; the caller must perform atomic counter consumption.
     *
     * @param string $secret Base32-encoded setup or enrolled secret
     * @param string $code Submitted decimal code, including any leading zeroes
     * @param int $period Positive duration of a TOTP time step in seconds
     * @param int $digits Required number of decimal digits
     * @param int $window Non-negative number of time steps to check on each side of the current step
     * @return int|null First matched counter, or null when the code has invalid format or no match
     * @throws \DivisionByZeroError If the supplied period is zero
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
     * Calculates a decimal TOTP code for a secret and time-step counter
     *
     * @param string $secret Base32-encoded setup or enrolled secret
     * @param int $counter Time-step counter used as the moving factor
     * @param int $digits Number of decimal digits in the generated code
     * @return string Decimal verification code left-padded with zeroes to the requested width
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
     * Decodes the supported Base32 characters into secret bytes
     *
     * Converts letters to uppercase, skips characters outside the alphabet,
     * and discards any trailing bits that do not form a complete byte.
     *
     * @param string $secret Base32-encoded secret
     * @return string Decoded binary secret
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
