<?php

namespace Lucinda\WebSecurity;

/**
 * Describes the non-authenticated outcomes of an OAuth2 account approval request
 *
 * Returned by an approval-provisioning DAO when an OAuth2 identity has no local
 * account yet. Approval itself is deliberately not represented here: once an
 * approved account exists, the DAO's normal resolve operation must return its
 * local user ID before another approval request is attempted.
 *
 * @see \Lucinda\WebSecurity\DAO\OAuth2\ApprovalProvisioning::requestApproval()
 * @see \Lucinda\WebSecurity\DAO\OAuth2\Login::resolve()
 */
enum OAuth2ApprovalStatus: string
{
    /**
     * An approval request exists and no login identity may be issued yet
     */
    case PENDING = "pending";

    /**
     * The provider identity is not eligible for a local account
     */
    case REJECTED = "rejected";
}
