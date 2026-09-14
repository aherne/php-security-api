<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Reports token JSON encoding, decoding, payload-structure, or IP-binding failures
 *
 * JSON failures retain the underlying JsonException as the previous
 * exception. Encryption, expiration, and renewal use separate exception
 * classes rather than subclasses of this exception.
 *
 * @see SynchronizerToken
 * @see EncryptionException
 * @see ExpiredException
 * @see RegenerationException
 */
class Exception extends \Exception
{
}
