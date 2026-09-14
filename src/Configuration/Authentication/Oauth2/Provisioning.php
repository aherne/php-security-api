<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

/**
 * Defines account creation policies selected by the oauth2 'provisioning' attribute
 */
enum Provisioning: string
{
    /**
     * Allows login only for an existing local account
     */
    case EXISTING_ONLY = "existing_only";
    /**
     * Requests approval before a local account can be created
     */
    case APPROVAL_REQUIRED = "approval_required";
    /**
     * Allows the provisioning DAO to create eligible local accounts
     */
    case AUTOMATIC = "automatic";
}