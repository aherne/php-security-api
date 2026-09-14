<?php

namespace Lucinda\WebSecurity\Security;

/**
 * Identifies detailed causes of rejected authentication operations
 *
 * Complements the broad login or logout result stored in a security packet.
 * The caller can use these values for diagnostics without recording raw
 * credentials, CSRF tokens, or OAuth2 state.
 *
 * @see \Lucinda\WebSecurity\Packets\Packet::getFailureReason()
 * @see \Lucinda\WebSecurity\Security\Authentication\ResultStatus
 */
enum FailureReason
{
    /**
     * A required form parameter is absent, empty according to PHP empty(), or not a string
     */
    case FORM_PARAMETERS_INVALID;
    /**
     * The submitted form CSRF token failed validation for the guest login context
     */
    case FORM_CSRF_REJECTED;
    /**
     * The form-login DAO did not return an accepted local user ID
     */
    case FORM_CREDENTIALS_REJECTED;
    /**
     * The logout request is not POST or its CSRF parameter is missing, empty, or not a string
     */
    case LOGOUT_PARAMETERS_INVALID;
    /**
     * The submitted logout CSRF token failed validation for the current user
     */
    case LOGOUT_CSRF_REJECTED;
    /**
     * The logout DAO rejected the operation
     */
    case LOGOUT_REJECTED;
    /**
     * Callback state is missing, malformed, or rejected by the provider-bound state store
     */
    case OAUTH_INVALID_STATE;
    /**
     * An error parameter was present in a callback whose state was accepted
     */
    case OAUTH_ERROR;
    /**
     * An accepted-state callback lacks a non-empty string authorization code
     */
    case OAUTH_PROVIDER_REJECTED;
    /**
     * No eligible local account was resolved and provisioning permits existing accounts only
     */
    case OAUTH_ACCOUNT_UNLISTED;
    /**
     * Automatic provisioning did not return a local account ID
     */
    case OAUTH_REGISTRATION_REJECTED;
    /**
     * Approval-based provisioning rejected the account request
     */
    case OAUTH_ACCOUNT_REJECTED;
}
