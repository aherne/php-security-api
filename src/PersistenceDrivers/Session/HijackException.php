<?php

namespace Lucinda\WebSecurity\PersistenceDrivers\Session;

/**
 * Reports a mismatch between the client IP and the IP recorded in the session
 *
 * A mismatch is treated as suspected session hijacking; it does not by itself
 * prove that the session was stolen.
 *
 * @see PersistenceDriver::load()
 */
class HijackException extends \Exception
{
}