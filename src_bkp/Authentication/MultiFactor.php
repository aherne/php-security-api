<?php

namespace Lucinda\WebSecurity\Authentication;

use Lucinda\WebSecurity\Request;

/**
 * Performs login/logout via database if path requested matches paths @ xml
 */
interface MultiFactor
{
    function verify(string|int $userID, Request $request): Result;
}
