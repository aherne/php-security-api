<?php

namespace Lucinda\WebSecurity\Security\MultiFactorAuthentication;

/**
 * Defines ResultStatus values.
 */
enum ResultStatus: int
{
    case NOT_REQUIRED = 1;
    case SETUP_REQUIRED = 2;
    case REQUIRED = 3;
    case SUCCEEDED = 4;
    case THROTTLED = 5;
    case FAILED = 6;
    case EXPIRED = 7;
}
