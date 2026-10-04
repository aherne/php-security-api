<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Reports failure to encode or decode a token representation
 *
 * Covers JSON conversion, encrypted-envelope parsing, authenticated
 * encryption, and authenticated decryption. It means no trustworthy decoded
 * token data was produced; it does not report validation of data that was
 * decoded successfully.
 *
 * @see Encryption
 * @see SynchronizerToken
 * @see ValidationException
 */
final class EncodingException extends \Exception
{
}
