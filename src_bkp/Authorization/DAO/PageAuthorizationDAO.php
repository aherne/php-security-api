<?php

namespace Lucinda\WebSecurity\Authorization\DAO;

/**
 * Defines blueprints for a DAO that checks requested page access levels in database.
 */
abstract class PageAuthorizationDAO
{
    protected ?int $pageID;

    /**
     * Saves detected database ID of page requested
     *
     * @param string $pageURL URL of page requested
     */
    public function __construct(string $pageURL)
    {
        $this->pageID = $this->detectID($pageURL);
    }

    /**
     * Detects database ID of page requested.
     *
     * @param  string $pageURL URL of page requested
     * @return int|null
     */
    abstract protected function detectID(string $pageURL): ?int;

    /**
     * Checks if current page does not require being logged in based on detected ID.
     *
     * @return boolean
     */
    abstract public function isPublic(): bool;

    /**
     * Gets detected id of page requested
     *
     * @return int|NULL
     */
    public function getID(): ?int
    {
        return $this->pageID;
    }
}
