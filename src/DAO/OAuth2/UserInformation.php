<?php

namespace Lucinda\WebSecurity\DAO\OAuth2;

/**
 * Defines the provider user information passed to OAuth2 account DAOs
 *
 * OAuth2Service::getUserInfo() returns an implementation of this interface.
 * The authentication workflow passes it to the configured OAuth2 DAO;
 * it is not registered through an XML attribute.
 *
 * @see \Lucinda\WebSecurity\OAuth2Service::getUserInfo()
 * @see Login
 * @see AutomaticProvisioning
 * @see ApprovalProvisioning
 */
interface UserInformation
{
    /**
     * Gets the user identifier assigned by the OAuth2 provider
     *
     * @return int|string Remote user ID, scoped to its provider rather than the local database
     */
    public function getId(): int|string;

    /**
     * Gets the user's display name supplied by the OAuth2 provider
     *
     * @return string Remote display name
     */
    public function getName(): string;

    /**
     * Gets the user's email address supplied by the OAuth2 provider
     *
     * @return string Remote email address
     */
    public function getEmail(): string;
}
