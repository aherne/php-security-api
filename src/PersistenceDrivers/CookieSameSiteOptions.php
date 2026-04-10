<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Available options for cookies samesite flag
 */
enum CookieSameSiteOptions: string
{
    case NONE = "None";
    case STRICT = "Strict";
    case LAX = "Lax";
}
