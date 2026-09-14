<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Reports malformed encrypted envelopes or failed cryptographic processing
 *
 * Also used by persistence drivers when a decrypted authentication payload
 * does not restore the expected authentication-state object. Expiration and
 * token JSON validation are reported through separate exception types.
 *
 * @see Encryption
 * @see \Lucinda\WebSecurity\PersistenceDrivers\SynchronizerToken\PersistenceDriver
 * @see \Lucinda\WebSecurity\PersistenceDrivers\RememberMe\PersistenceDriver
 */
class EncryptionException extends \Exception
{
}
