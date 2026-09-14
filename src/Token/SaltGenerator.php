<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Generates a fixed-length shared secret for token encryption
 *
 * Construction generates random bytes, converts them to Base64 text,
 * replaces '+' with '.', and truncates the result to the requested length.
 * Despite the class name, the value is a secret used for key derivation,
 * not a public per-token salt. It may contain '/' and is not URL-safe Base64.
 *
 * @see Encryption
 * @see SynchronizerToken
 */
class SaltGenerator
{
    private string $salt;

    /**
     * Generates and stores a shared secret of the requested character length
     *
     * @param int $length Positive output length in characters; also the number of random bytes requested
     * @throws \ValueError If the requested length is less than one
     * @throws \Exception If secure random bytes cannot be generated
     */
    public function __construct(int $length)
    {
        $this->setSalt($length);
    }

    /**
     * Generates random bytes and derives the fixed-length secret text
     *
     * @param int $length Positive output length in characters; also the number of random bytes requested
     * @throws \ValueError If the requested length is less than one
     * @throws \Exception If secure random bytes cannot be generated
     */
    private function setSalt(int $length): void
    {
        $this->salt = substr(strtr(base64_encode(random_bytes($length)), '+', '.'), 0, $length);
    }

    /**
     * Gets the shared secret generated during construction
     *
     * Reading the value does not generate a new secret. Treat it as key material
     * and exclude it from logs.
     *
     * @return string Generated shared secret with the requested character length
     */
    public function getSalt(): string
    {
        return $this->salt;
    }
}
