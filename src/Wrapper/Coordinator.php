<?php

namespace Lucinda\WebSecurity\Wrapper;

use Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver;
use Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo;
use Lucinda\WebSecurity\PersistenceDrivers\Exception;

/**
 * Coordinates persistence writes and cleanup for authentication workflows
 *
 * Binds authentication and MFA wrapper state changes to the supplied
 * persistence-driver implementations.
 *
 * Saves authentication state through selected drivers. If saving fails,
 * attempts to clear every attempted driver in reverse order, including
 * the driver whose save failed. Cleanup continues after individual failures.
 *
 * Cleanup is best-effort compensation, not an atomic transaction:
 * previously stored state is not restored.
 *
 * @internal
 * @see Authentication
 * @see MultiFactorAuthentication
 * @see \Lucinda\WebSecurity\PersistenceDrivers\PersistenceDriver
 */
final class Coordinator
{
    /**
     * @var PersistenceDriver[] Drivers in the order in which saves are attempted
     */
    private array $drivers;

    /**
     * Registers the persistence drivers to coordinate
     *
     * @param PersistenceDriver[] $drivers Drivers in save order; cleanup uses the reverse order
     */
    public function __construct(array $drivers)
    {
        $this->drivers = $drivers;
    }

    /**
     * Saves authentication state through drivers not excluded by the skip predicate
     *
     * If a save or the predicate throws, attempts cleanup of all drivers whose
     * save was attempted. Rethrows the original failure when cleanup succeeds.
     * If cleanup also fails, throws a persistence exception with the original
     * failure as its previous exception and the first cleanup failure's message.
     *
     * @param LoggedInUserInfo $userInfo Authentication state to persist
     * @param (callable(PersistenceDriver):bool)|null $shouldSkip Predicate returning true to skip a driver, or null
     * @throws Exception If saving fails and cleanup is incomplete
     * @throws \Throwable The original save or predicate failure when cleanup succeeds
     */
    public function save(
        LoggedInUserInfo $userInfo,
        ?callable $shouldSkip = null
    ): void {
        $attemptedDrivers = [];

        try {
            foreach ($this->drivers as $driver) {
                if ($shouldSkip !== null && $shouldSkip($driver)) {
                    continue;
                }

                $attemptedDrivers[] = $driver;
                $driver->save($userInfo);
            }
        } catch (\Throwable $saveFailure) {
            $rollbackFailure = $this->clearDrivers($attemptedDrivers);

            if ($rollbackFailure !== null) {
                throw new Exception(
                    "Persistence save failed and rollback was incomplete: "
                    .$rollbackFailure->getMessage(),
                    0,
                    $saveFailure
                );
            }

            throw $saveFailure;
        }
    }

    /**
     * Clears all registered drivers in reverse order
     *
     * Attempts every driver even if an earlier cleanup operation throws.
     *
     * @throws \Throwable The first cleanup failure encountered, after all drivers have been attempted
     */
    public function clear(): void
    {
        $failure = $this->clearDrivers($this->drivers);

        if ($failure !== null) {
            throw $failure;
        }
    }

    /**
     * Attempts cleanup of every supplied driver in reverse order
     *
     * Retains the first failure and continues clearing the remaining drivers.
     *
     * @param PersistenceDriver[] $drivers Drivers to clear, supplied in save order
     * @return \Throwable|null First cleanup failure, or null when every clear operation succeeded
     */
    private function clearDrivers(array $drivers): ?\Throwable
    {
        $failure = null;

        foreach (array_reverse($drivers) as $driver) {
            try {
                $driver->clear();
            } catch (\Throwable $exception) {
                $failure ??= $exception;
            }
        }

        return $failure;
    }
}
