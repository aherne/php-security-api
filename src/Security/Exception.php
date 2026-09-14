<?php
namespace Lucinda\WebSecurity\Security;

/**
 * Reports missing security dependencies or invalid authentication-state input
 *
 * Expected login, logout, and access rejections are represented by workflow
 * results instead. Failures originating in external DAOs or services may
 * propagate using their own exception types.
 *
 * @see Authentication
 * @see Authorization
 * @see \Lucinda\WebSecurity\PersistenceDrivers\LoggedInUserInfo
 */
class Exception extends \Exception
{}