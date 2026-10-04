<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Reports that successfully decoded token data is invalid for its context
 *
 * Covers invalid payload structure or types, failed security-context checks
 * such as IP binding, and payloads that cannot be restored as the application
 * state expected by a persistence driver. Encoding and decoding failures use
 * EncodingException instead.
 *
 * Expiration and renewal retain dedicated exception types because persistence
 * drivers handle those states differently from an invalid token.
 *
 * @see SynchronizerToken
 * @see EncodingException
 * @see ExpiredException
 * @see RegenerationException
 */
final class ValidationException extends \Exception
{
}
