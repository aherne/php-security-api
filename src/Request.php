<?php

namespace Lucinda\WebSecurity;

/**
 * Holds the normalized request data consumed by the security workflow
 *
 * The host application creates this transport object from its HTTP framework
 * and supplies route, context path, client IP, method, parameters, and an
 * optional bearer token. The security package deliberately does not read PHP
 * request superglobals through this object.
 *
 * URI, context path, IP address, and method must be assigned before their
 * getters—or Wrapper—are used. Parameters and access token default to an empty
 * array and empty string respectively.
 *
 * @see Wrapper::__construct()
 */
final class Request
{
    /**
     * Application-relative route being processed
     */
    private string $uri;

    /**
     * URL path prefix prepended to locally configured callbacks
     */
    private string $contextPath;

    /**
     * Normalized client IP used by token binding, sessions, and throttlers
     */
    private string $ipAddress;

    /**
     * HTTP request method, conventionally supplied in uppercase
     */
    private string $method;

    /**
     * Explicit bearer token, or an empty string when none was supplied
     */
    private string $accessToken = "";

    /**
     * @var array<string,mixed> Normalized request parameters keyed by field name
     */
    private array $parameters=[];

    /**
     * Sets the application-relative route requested by the client
     *
     * The value is compared directly with configured authentication, MFA, and
     * authorization routes; it should therefore use the same normalization.
     *
     * @param string $uri Route without the external application context path
     */
    public function setUri(string $uri): void
    {
        $this->uri = $uri;
    }

    /**
     * Sets the application context path used to build callback URLs
     *
     * @param string $contextPath URL path prefix, without a required trailing slash
     */
    public function setContextPath(string $contextPath): void
    {
        $this->contextPath = $contextPath;
    }

    /**
     * Sets the normalized client IP address
     *
     * The host application remains responsible for safely resolving trusted
     * proxy headers before assigning this value.
     *
     * @param string $ipAddress Client IPv4 or IPv6 textual representation
     */
    public function setIpAddress(string $ipAddress): void
    {
        $this->ipAddress = $ipAddress;
    }

    /**
     * Sets the HTTP request method
     *
     * @param string $method Normalized method such as `GET` or `POST`
     */
    public function setMethod(string $method): void
    {
        $this->method = $method;
    }

    /**
     * Sets request parameters available to authentication and MFA handlers
     *
     * @param array<string,mixed> $parameters Parameters keyed by their configured field names
     */
    public function setParameters(array $parameters): void
    {
        $this->parameters = $parameters;
    }

    /**
     * Sets the authentication token extracted from a Bearer authorization header
     *
     * Supply only the token value, without the `Bearer` scheme prefix.
     *
     * @param string $accessToken Encoded persistence token, or an empty string when absent
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets the application-relative route requested by the client
     *
     * @return string Route previously assigned through setUri()
     */
    public function getUri(): string
    {
        return $this->uri;
    }

    /**
     * Gets the application context path used for local callback URLs
     *
     * @return string Context path previously assigned through setContextPath()
     */
    public function getContextPath(): string
    {
        return $this->contextPath;
    }

    /**
     * Gets the normalized client IP address
     *
     * @return string Address previously assigned through setIpAddress()
     */
    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    /**
     * Gets the normalized HTTP request method
     *
     * @return string Method previously assigned through setMethod()
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * Gets normalized request parameters
     *
     * @return array<string,mixed> Parameters supplied through setParameters(), or an empty array by default
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * Gets the explicit bearer authentication token
     *
     * @return string Token supplied through setAccessToken(), or an empty string by default
     */
    public function getAccessToken(): string
    {
        return $this->accessToken;
    }
}
