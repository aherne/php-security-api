<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Encapsulates logout request data
 */
class LogoutRequest extends UrlTargetRequest
{
    /**
     * Gets default logout source page, if none set in XML
     *
     * @return string
     */
    protected function getDefaultSourcePage(): string
    {
        return "logout";
    }

    /**
     * Gets default logout destination page, if none set in XML
     *
     * @return string
     */
    protected function getDefaultDestinationPage(): string
    {
        return "login";
    }
}
