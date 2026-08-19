<?php

namespace Lucinda\WebSecurity\Configuration\Authentication\Oauth2;

enum Provisioning: string
{
    case EXISTING_ONLY = "existing_only";
    case APPROVAL_REQUIRED = "approval_required";
    case AUTOMATIC = "automatic";
}