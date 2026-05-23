<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

/**
 * Exception thrown when session is registered on a different ip
 */
class HijackException extends \Exception
{
}
