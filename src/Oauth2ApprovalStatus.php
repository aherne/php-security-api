<?php

namespace Lucinda\WebSecurity;

enum Oauth2ApprovalStatus: string
{
    case PENDING = "pending";
    case REJECTED = "rejected";
}