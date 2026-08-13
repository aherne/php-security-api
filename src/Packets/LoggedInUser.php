<?php

namespace Lucinda\WebSecurity\Packets;

/**
 * Holds info about logged in user
 */
final class LoggedInUser extends Packet
{
    /**
     * Forces setting user id
     * 
     * @param int|string $userID
     */
    public function __construct(int|string $userID)
    {
        $this->setUserID($userID);
    }
}