<?php

namespace Lucinda\WebSecurity\Security\Authentication;

/**
 * Enum that contains all available authentication result statuses via following constants:
 * - LOGIN_OK: login was successful
 * - LOGIN_FAILED: login was unsuccessful (eg: password was wrong)
 * - LOGIN_THROTTLED: login was throttled (too many failure attempts)
 * - LOGOUT_OK: logout was successful
 * - LOGOUT_FAILED: logout was unsuccessful (eg: user wasn't logged in)
 * - DEFERRED: login was deferred to a third party provider (eg: OAuth2)
 */
enum ResultStatus: int
{
    case IDENTITY_VERIFIED = 7;
    case LOGIN_OK = 1;
    case LOGIN_FAILED = 2;
    case LOGIN_THROTTLED = 6;
    case LOGOUT_OK = 3;
    case LOGOUT_FAILED = 4;
    case DEFERRED = 5;
}
