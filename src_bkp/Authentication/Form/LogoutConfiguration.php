<?php

namespace Lucinda\WebSecurity\Authentication\Form;

/**
 * Encapsulates logout request configuration by matching data in xml
 */
class LogoutConfiguration extends UrlTargetConfiguration
{
    /**
     * Get name of XML sub-tag holding source/target url values
     *
     * @return string
     */
    protected function getTagName(): string
    {
        return "logout";
    }
}
