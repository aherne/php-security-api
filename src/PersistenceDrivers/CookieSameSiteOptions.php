<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

/**
 * Defines supported values for the cookie SameSite attribute
 *
 * The backed values are passed to PHP cookie configuration functions.
 *
 * @see CookieSecurityOptions
 */
enum CookieSameSiteOptions: string
{
    /**
     * Selects the None SameSite policy
     */
    case NONE = "None";
    /**
     * Selects the Strict SameSite policy
     */
    case STRICT = "Strict";
    /**
     * Selects the Lax SameSite policy
     */
    case LAX = "Lax";
}
