<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Encapsulates data encryption over openssl using AES-256 cypher.
 */
class Encryption
{
    public const CYPHER_METHOD = "AES-256-GCM";
    private const VERSION = "v2";
    private const TAG_LENGTH = 16;

    private string $key;

    /**
     * Creates an encryption instance using a salt password that's going to be used in encryption/decryption.
     *
     * @param string $salt Encryption password.
     */
    public function __construct(string $salt)
    {
        // Produces the 32-byte key required by AES-256.
        $this->key = hash("sha256", $salt, true);
    }

    /**
     * Encrypts data and returns encrypted value.
     *
     * @param  string $data Value to encrypt.
     * @throws EncryptionException If encryption fails.
     * @return string Encrypted representation of data.
     */
    public function encrypt(string $data): string
    {
        $iv = random_bytes(openssl_cipher_iv_length(self::CYPHER_METHOD));

        $ciphertext = openssl_encrypt(
            $data,
            self::CYPHER_METHOD,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::VERSION,
            self::TAG_LENGTH
        );

        if ($ciphertext === false) {
            throw new EncryptionException("Encryption failed!");
        }

        return implode(".", [
            self::VERSION,
            base64_encode($iv),
            base64_encode($tag),
            base64_encode($ciphertext)
        ]);
    }

    /**
     * Decrypts data and returns decrypted value.
     *
     * @param  string $data Encrypted representation of data.
     * @throws EncryptionException If decryption fails.
     * @return string Decrypted data.
     */
    public function decrypt(string $data): string
    {
        $parts = explode(".", $data);

        if (count($parts) !== 4 || $parts[0] !== self::VERSION) {
            throw new EncryptionException("Invalid encrypted value!");
        }

        $iv = base64_decode($parts[1], true);
        $tag = base64_decode($parts[2], true);
        $ciphertext = base64_decode($parts[3], true);

        if (
            $iv === false
            || $tag === false
            || $ciphertext === false
            || strlen($iv) !== openssl_cipher_iv_length(self::CYPHER_METHOD)
            || strlen($tag) !== self::TAG_LENGTH
        ) {
            throw new EncryptionException("Invalid encrypted value!");
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CYPHER_METHOD,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            self::VERSION
        );

        if ($plaintext === false) {
            throw new EncryptionException("Decryption failed!");
        }

        return $plaintext;
    }
}
