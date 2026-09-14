<?php

namespace Lucinda\WebSecurity\Security\Authorization;

/**
 * Defines decisions produced by resource-authorization checks
 *
 * These workflow values are not HTTP status codes. A corresponding result
 * may include a failure callback for the enclosing wrapper to handle.
 *
 * @see Result
 * @see \Lucinda\WebSecurity\Packets\Security
 */
enum ResultStatus: int
{
    /**
     * The requested resource is accessible to the current user or guest
     */
    case OK = 6;
    /**
     * A guest does not satisfy the requested resource's access requirements
     */
    case UNAUTHORIZED = 7;
    /**
     * An authenticated user does not satisfy the requested resource's access requirements
     */
    case FORBIDDEN = 8;
    /**
     * The requested resource or its applicable route-role policy was not found
     */
    case NOT_FOUND = 9;
}
