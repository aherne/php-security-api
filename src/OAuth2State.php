<?php

namespace Lucinda\WebSecurity;

/**
 * Defines persistence for one-time OAuth2 authorization state
 *
 * Implementations protect the interval between the initial provider redirect
 * and its callback. State values are bound to a configured provider name so a
 * value created for one provider cannot authorize a callback from another.
 *
 * The store may use sessions, a database, cache, or another server-side
 * mechanism, but consume() must validate and delete atomically to prevent
 * replay. Expired state must never be accepted.
 *
 * @see OAuth2Service::getAuthorizationCodeEndpoint()
 * @see \Lucinda\WebSecurity\Security\Authentication\Oauth2
 */
interface OAuth2State
{
    /**
     * Saves state for one provider and login attempt
     *
     * A state value is generated immediately before the OAuth2 authorization
     * redirect. Implementations should preserve the full value without lossy
     * normalization and may replace an existing identical key.
     *
     * @param string $state Cryptographically random state value to persist
     * @param string $vendorName Configured OAuth2 provider name to which the state is bound
     * @param int $validUntil Absolute Unix timestamp in seconds after which the state must be rejected
     * @throws \Throwable If the state cannot be persisted
     */
    public function save(string $state, string $vendorName, int $validUntil): void;

    /**
     * Atomically validates and consumes state for a provider callback
     *
     * Returns true exactly once when the state exists, belongs to the supplied
     * provider, and has not expired. Whether accepted or expired, a located
     * value should be removed so it cannot be replayed. Unknown, mismatched,
     * expired, or previously consumed state returns false.
     *
     * @param string $state State value received from the OAuth2 callback
     * @param string $vendorName Configured provider name handling the callback
     * @return bool True only when a live matching state was atomically consumed
     * @throws \Throwable If the state store cannot complete the operation
     */
    public function consume(string $state, string $vendorName): bool;
}
