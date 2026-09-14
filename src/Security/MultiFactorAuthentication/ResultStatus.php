<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

/**
 * Defines outcomes of MFA policy evaluation, enrollment, and verification
 *
 * The status identifies the next MFA step or its result. Throttling is
 * carried in a throttling packet; other outcomes use an MFA packet.
 *
 * @see \Lucinda\WebSecurity\Packets\MultiFactor
 * @see \Lucinda\WebSecurity\Packets\Throttling
 */
enum ResultStatus: int
{
    /**
     * The MFA DAO reports that this user does not currently require MFA
     */
    case NOT_REQUIRED = 1;
    /**
     * No enrolled factor exists; enrollment and confirmation are required
     */
    case SETUP_REQUIRED = 2;
    /**
     * An enrolled factor must be verified before authentication can proceed
     */
    case REQUIRED = 3;
    /**
     * A submitted code was verified and its counter consumed; setup also enabled the factor
     */
    case SUCCEEDED = 4;
    /**
     * The MFA throttler blocked further enrollment or verification attempts
     */
    case THROTTLED = 5;
    /**
     * The submitted code did not match or its counter could not be consumed
     */
    case FAILED = 6;
    /**
     * The pending-MFA deadline is missing or has been reached; authentication must restart
     */
    case EXPIRED = 7;
}
