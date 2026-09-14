<?php

namespace Lucinda\WebSecurity\Packets;

/**
 * Represents the guest login form state and supplies its CSRF token
 *
 * The caller can include the token when submitting the login form.
 *
 * @see \Lucinda\WebSecurity\Wrapper::getOutcome()
 */
final class GuestUser extends Packet
{
    private string $csrfToken;

    /**
     * Creates the guest login form outcome
     *
     * @param string $csrfToken CSRF token generated for the guest login form
     */
    public function __construct(string $csrfToken)
    {
        $this->csrfToken = $csrfToken;
    }

    /**
     * Gets the CSRF token to submit with the guest login form
     *
     * @return string Guest login form CSRF token
     */
    public function getCsrfToken(): string
    {
        return $this->csrfToken;
    }
}