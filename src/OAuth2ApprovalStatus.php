<?php

namespace Lucinda\WebSecurity;

enum OAuth2ApprovalStatus: string
{
    case PENDING = "pending";
    case REJECTED = "rejected";
}