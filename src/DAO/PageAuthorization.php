<?php

namespace Lucinda\WebSecurity\DAO;

/**
 * Defines the DAO base class for resolving requested pages and their public-access policy
 *
 * Register the concrete subclass through the 'page_dao' attribute
 * of security > authorization > by_dao.
 * The library constructs it with the requested route.
 *
 * @see \Lucinda\WebSecurity\Configuration\Authorization\ByDAO
 */
abstract class PageAuthorization
{
    protected ?int $pageID;

    /**
     * Resolves and stores the database ID of the requested page
     *
     * @param string $pageURL Requested route supplied by Request::getUri()
     */
    public function __construct(string $pageURL)
    {
        $this->pageID = $this->detectID($pageURL);
    }

    /**
     * Looks up the database ID of the requested page
     *
     * @param string $pageURL Requested route to look up
     * @return int|null Non-zero page ID when found; null when the route has no matching page
     */
    abstract protected function detectID(string $pageURL): ?int;

    /**
     * Checks whether the resolved page permits access without authentication
     *
     * The authorization workflow calls this after a page ID has been found.
     * Public pages bypass the user-specific permission check.
     *
     * @return bool True for a public page; false when authentication and permission checks are required
     */
    abstract public function isPublic(): bool;

    /**
     * Gets the resolved database ID of the requested page
     *
     * @return int|null Page ID, or null when the page was not found
     */
    public function getID(): ?int
    {
        return $this->pageID;
    }
}
