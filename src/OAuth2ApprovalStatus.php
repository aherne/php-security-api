<?php

namespace Lucinda\WebSecurity;

/**
 * Defines accepted options in new account approval statuses
 */
enum OAuth2ApprovalStatus: string
{
    case PENDING = "pending";
    case REJECTED = "rejected";
}