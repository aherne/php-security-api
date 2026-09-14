<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Defines the contract for persisting authentication state across requests
 *
 * The stored state may represent pending MFA or completed authentication.
 * Implementations handle storage and cleanup; they do not decide whether
 * the authentication workflow has completed.
 *
 * @see LoggedInUserInfo
 * @see AuthenticationStage
 */
interface PersistenceDriver
{    
    /**
     * Restores authentication state from this persistence mechanism
     *
     * Implementations may start sessions, refresh deadlines, renew tokens,
     * or remove expired data while loading.
     *
     * @return LoggedInUserInfo|null Stored authentication state, or null when absent or expired
     * @throws \Throwable If the implementation cannot load or validate the stored state
     */
    public function load(): ?LoggedInUserInfo;

    /**
     * Persists authentication state through this mechanism
     *
     * A failure may occur after partial changes; callers coordinating multiple
     * drivers must handle cleanup of attempted writes.
     *
     * @param LoggedInUserInfo $authentication Authentication state to persist
     * @throws \Throwable If the implementation cannot save the authentication state
     */
    public function save(LoggedInUserInfo $authentication): void;

    /**
     * Clears authentication data according to this mechanism's cleanup rules
     *
     * The cleanup scope and ability to invalidate previously issued credentials
     * depend on the implementation.
     *
     * @throws \Throwable If the implementation cannot complete cleanup
     */
    public function clear(): void;
}
