<?php

namespace Lucinda\WebSecurity\Authentication\MultiFactor;

/**
 * Enum that contains all available authentication result statuses via following constants:
 */
enum ResultStatus: int
{
    case NOT_REQUIRED = 1;
    case SETUP_REQUIRED = 2;
    case REQUIRED = 3;
    case SUCCEEDED = 4;
    case THROTTLED = 5;
}
