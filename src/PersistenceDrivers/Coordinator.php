<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

final class Coordinator
{
    private array $drivers;

    /**
     * @param PersistenceDriver[] $drivers
     */
    public function __construct(array $drivers)
    {
        $this->drivers = $drivers;
    }

    /**
     * @param null|callable(PersistenceDriver):bool $filter
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

    public function clear(): void
    {
        $failure = $this->clearDrivers($this->drivers);

        if ($failure !== null) {
            throw $failure;
        }
    }

    /**
     * @param PersistenceDriver[] $drivers
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