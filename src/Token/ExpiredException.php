<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Signals that the current time exceeds a token's embedded expiration timestamp
 *
 * Expiration is checked before the renewal threshold. An expired token is
 * not offered for renewal through RegenerationException.
 *
 * @see SynchronizerToken::decode()
 * @see RegenerationException
 */
class ExpiredException extends \Exception
{
}
