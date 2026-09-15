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
interface PageAuthorization
{
    /**
     * Checks whether the resolved page permits access without authentication
     *
     * The authorization workflow calls this after a page ID has been found.
     * Public pages bypass the user-specific permission check.
     *
     * @param int $pageID ID of the respective page already detected.
     * @return bool True for a public page; false when authentication and permission checks are required
     */
    public function isPublic(int $pageID): bool;

    /**
     * Gets the database ID of the requested page
     *
     * @param string $pageURL Requested route supplied by Request::getUri()
     * @return int|null Page ID, or null when the page was not found
     */
    public function getID(string $pageURL): ?int;
}
