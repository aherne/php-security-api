<?php

namespace Lucinda\WebSecurity\Security\Authentication;

/**
 * Defines outcomes of login and logout processing
 *
 * Statuses describe workflow decisions, not HTTP status codes. Primary
 * identity verification is distinct from completed login. Detailed rejection
 * causes may be supplied separately through FailureReason.
 *
 * @see \Lucinda\WebSecurity\Packets\Security
 * @see \Lucinda\WebSecurity\Security\FailureReason
 */
enum ResultStatus: int
{
    /**
     * Primary identity was verified; the wrapper must still evaluate MFA requirements
     */
    case IDENTITY_VERIFIED = 7;
    /**
     * Login was accepted; the enclosing wrapper performs authentication persistence
     */
    case LOGIN_OK = 1;
    /**
     * Login was rejected; an attached failure reason may explain why
     */
    case LOGIN_FAILED = 2;
    /**
     * The form-login throttler blocked further attempts
     */
    case LOGIN_THROTTLED = 6;
    /**
     * Account provisioning awaits approval; this does not mean MFA is pending
     */
    case LOGIN_PENDING = 8;
    /**
     * The logout DAO accepted the operation; the wrapper must still clear persistence
     */
    case LOGOUT_OK = 3;
    /**
     * Logout was rejected by request validation, CSRF validation, or the logout DAO
     */
    case LOGOUT_FAILED = 4;
    /**
     * Continue through the callback, such as provider authorization or an already-satisfied login/logout request
     */
    case DEFERRED = 5;
}
