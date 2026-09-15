<?php

namespace Test\Lucinda\WebSecurity\Support;

use Lucinda\WebSecurity\Configuration;
use Lucinda\WebSecurity\Request;

final class Fixture
{
    private const XML_FILE = __DIR__."/../mocks/fixtures.xml";
    private static ?\SimpleXMLElement $document = null;

    public static function configuration(bool $withMfa = false): Configuration
    {
        return new Configuration(self::xml($withMfa));
    }

    public static function xml(bool $withMfa = false): \SimpleXMLElement
    {
        $fixture = $withMfa ? "application-mfa" : "application";

        return self::node($fixture);
    }

    public static function node(string $fixture): \SimpleXMLElement
    {
        if (!preg_match('/\A[a-z0-9-]+\z/', $fixture)) {
            throw new \InvalidArgumentException("Invalid XML test fixture name: ".$fixture);
        }

        $document = self::document();
        $matches = $document->xpath("//*[@fixture='".$fixture."']");
        if (empty($matches)) {
            throw new \RuntimeException("Unknown XML test fixture: ".$fixture);
        }

        $xml = $matches[0]->asXML();
        if ($xml === false) {
            throw new \RuntimeException("Unable to copy XML test fixture: ".$fixture);
        }

        $node = new \SimpleXMLElement($xml);
        unset($node["fixture"]);

        return $node;
    }

    private static function document(): \SimpleXMLElement
    {
        if (self::$document === null) {
            $document = simplexml_load_file(self::XML_FILE, \SimpleXMLElement::class, LIBXML_NONET);
            if ($document === false) {
                throw new \RuntimeException("Unable to load XML test fixtures");
            }
            self::$document = $document;
        }

        return self::$document;
    }

    public static function request(
        string $uri = "home",
        string $method = "GET",
        array $parameters = [],
        string $accessToken = ""
    ): Request {
        $request = new Request();
        $request->setUri($uri);
        $request->setContextPath("/app/");
        $request->setIpAddress("127.0.0.1");
        $request->setMethod($method);
        $request->setParameters($parameters);
        $request->setAccessToken($accessToken);

        return $request;
    }
}
