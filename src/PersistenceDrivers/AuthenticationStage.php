<?php

namespace Lucinda\WebSecurity\PersistenceDrivers;

enum AuthenticationStage: string
{
    case PENDING_MFA = "pending_mfa";
    case AUTHENTICATED = "authenticated";
}