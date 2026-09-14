<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Protects token plaintext with AES-256-GCM authenticated encryption
 *
 * Derives a 32-byte binary key by hashing the supplied shared secret with
 * SHA-256. Each encryption uses a fresh random IV and a 16-byte tag.
 *
 * The textual envelope contains a version followed by Base64-encoded IV,
 * tag, and ciphertext, separated by periods. The version is also supplied
 * as authenticated additional data. This helper does not interpret payloads
 * or enforce token expiration and IP binding.
 *
 * @see SynchronizerToken
 * @see EncryptionException
 */
class Encryption
{
    /**
     * OpenSSL cipher used to encrypt and authenticate the plaintext
     */
    public const CYPHER_METHOD = "AES-256-GCM";
    /**
     * Envelope version also authenticated as additional data
     */
    private const VERSION = "v2";
    /**
     * Required GCM authentication-tag length in bytes
     */
    private const TAG_LENGTH = 16;

    /**
     * @var string 32-byte binary encryption key derived from the shared secret
     */
    private string $key;

    /**
     * Derives the encryption key from the supplied shared secret
     *
     * Hashing produces the key bytes; it does not generate a random secret.
     *
     * @param string $salt Shared encryption secret used by both encrypting and decrypting instances
     */
    public function __construct(string $salt)
    {
        // Produces the 32-byte key required by AES-256.
        $this->key = hash("sha256", $salt, true);
    }

    /**
     * Encrypts and authenticates plaintext using a fresh random IV
     *
     * The returned envelope uses ordinary Base64 components, not URL-safe
     * Base64. No token-specific metadata or expiration is added by this helper.
     *
     * @param string $data Plaintext bytes to encrypt; JSON encoding is the caller's responsibility
     * @return string Version, Base64 IV, Base64 tag, and Base64 ciphertext separated by periods
     * @throws EncryptionException If OpenSSL cannot encrypt the plaintext
     * @throws \Exception If secure random bytes for the IV cannot be generated
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
     * Validates the encrypted envelope and authenticates it before returning plaintext
     *
     * Requires the expected version, valid Base64 components, and the configured
     * IV and tag lengths. Does not decode JSON or validate token metadata.
     *
     * @param string $data Versioned encrypted envelope produced by encrypt()
     * @return string Authenticated plaintext bytes
     * @throws EncryptionException If envelope validation or authenticated decryption fails
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
