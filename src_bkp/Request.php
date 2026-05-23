<?php

namespace Lucinda\WebSecurity;

/**
 * Encapsulates user request information
 */
class Request
{
    private string $uri;
    private string $contextPath;
    private string $ipAddress;
    private string $method;
    private string $accessToken;
    /**
     * @var array<string,mixed>
     */
    private array $parameters=[];

    /**
     * Sets relative URI (page) requested by client
     *
     * @param string $uri
     */
    public function setUri(string $uri): void
    {
        $this->uri = $uri;
    }

    /**
     * Sets context path that prefixes page requested by client,
     *
     * @param string $contextPath
     */
    public function setContextPath(string $contextPath): void
    {
        $this->contextPath = $contextPath;
    }

    /**
     * Sets ip address used by client
     *
     * @param string $ipAddress
     */
    public function setIpAddress(string $ipAddress): void
    {
        $this->ipAddress = $ipAddress;
    }

    /**
     * Sets HTTP request method used by client in request
     *
     * @param string $method
     */
    public function setMethod(string $method): void
    {
        $this->method = $method;
    }

    /**
     * Sets request parameters that came along with http method
     *
     * @param array<string,mixed> $parameters
     */
    public function setParameters(array $parameters): void
    {
        $this->parameters = $parameters;
    }

    /**
     * Sets access token value based on contents of HTTP authorization header of "bearer" type
     *
     * @param string $accessToken
     */
    public function setAccessToken(string $accessToken): void
    {
        $this->accessToken = $accessToken;
    }

    /**
     * Gets relative URI (page) requested by client
     *
     * @return string
     */
    public function getUri(): string
    {
        return $this->uri;
    }

    /**
     * Gets context path that prefixes page requested by client,
     *
     * @return string
     */
    public function getContextPath(): string
    {
        return $this->contextPath;
    }

    /**
     * Gets ip address used by client
     *
     * @return string
     */
    public function getIpAddress(): string
    {
        return $this->ipAddress;
    }

    /**
     * Gets HTTP request method used by client in request
     *
     * @return string
     */
    public function getMethod(): string
    {
        return $this->method;
    }

    /**
     * Gets request parameters that came along with http method
     *
     * @return array<string,mixed>
     */
    public function getParameters(): array
    {
        return $this->parameters;
    }

    /**
     * Gets access token value.
     *
     * @return string
     */
    public function getAccessToken(): string
    {
        return $this->accessToken;
    }
}
