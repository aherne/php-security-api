<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Identifies whether persisted authentication awaits MFA or is complete
 *
 * The stage is stored alongside the local user ID and optional deadline.
 *
 * @see LoggedInUserInfo
 */
enum AuthenticationStage: string
{
    /**
     * Primary identity verification succeeded, but required MFA is not complete
     */
    case PENDING_MFA = "pending_mfa";
    /**
     * All authentication requirements for the current workflow have been satisfied
     */
    case AUTHENTICATED = "authenticated";
}