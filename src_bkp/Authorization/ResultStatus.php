<?php

namespace Lucinda\WebSecurity\Authorization;

/**
 * Enum that contains all available authorization statuses via following constants:
 * - OK: authorization was successful
 * - UNAUTHORIZED: authorization failed because user is not authenticated
 * - FORBIDDEN: authorization failed because authenticated user is not allowed access to requested resource
 * - NOT_FOUND: authorization failed because no authorization policy could be found for requested resource
 */
enum ResultStatus: int
{
    case OK = 6;
    case UNAUTHORIZED = 7;
    case FORBIDDEN = 8;
    case NOT_FOUND = 9;
}
