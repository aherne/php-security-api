<?php

namespace Lucinda\WebSecurity\Token;

/**
 * Signals that an unexpired token has exceeded its configured renewal age
 *
 * SynchronizerToken throws this after validating the encrypted envelope,
 * payload structure, IP binding, and expiration. Carries the original uid
 * payload so the caller can encode a replacement; throwing this exception
 * does not itself issue a token.
 *
 * @see SynchronizerToken::decode()
 * @see SynchronizerToken::encode()
 */
class RegenerationException extends \Exception
{
    /**
     * @var mixed Original payload to carry into a replacement token; assigned before retrieval
     */
    private mixed $payload;

    /**
     * Attaches the original payload for the caller to reuse during renewal
     *
     * SynchronizerToken supplies the validated uid value before converting
     * empty values to null.
     *
     * @param mixed $payload Original token payload to preserve in a replacement
     */
    public function setPayload(mixed $payload): void
    {
        $this->payload= $payload;
    }

    /**
     * Gets the original payload attached for token renewal
     *
     * Requires setPayload() to have been called. Reading the payload does not
     * encode or persist a replacement token.
     *
     * @return mixed Original payload supplied through setPayload()
     */
    public function getPayload(): mixed
    {
        return $this->payload;
    }
}
