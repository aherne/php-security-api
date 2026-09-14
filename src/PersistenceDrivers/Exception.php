<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Reports failures while saving, loading, or clearing persisted authentication
 *
 * Also reports incomplete cleanup after a coordinated save failure.
 * Token validation and session IP mismatches have separate exception types.
 *
 * @see \Lucinda\WebSecurity\Wrapper\Coordinator
 * @see Session\HijackException
 */
class Exception extends \Exception
{
    
}