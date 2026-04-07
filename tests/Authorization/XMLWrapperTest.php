<?php

namespace Test\Lucinda\WebSecurity\Authorization;

use Lucinda\WebSecurity\Request;
use Lucinda\UnitTest\Result;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\WebSecurity\Authorization\XMLWrapper;

class XMLWrapperTest
{
    private $xml1;
    private $xml2;

    public function __construct()
    {
        $xml1 = \simplexml_load_string(
            '
<xml>
    <security>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <users roles="GUEST">
        <user id="1" roles="USER"/>
    </users>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );
        $this->xml1 = $xml1->security;
        $xml2 = \simplexml_load_string(
            '
<xml>
    <security>
        <authentication>
            <form dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserRolesDAO"/>
        </authentication>
        <authorization>
            <by_route/>
        </authorization>
    </security>
    <routes>
        <route id="login" roles="GUEST,USER"/>
        <route id="index" roles="USER"/>
        <route id="logout" roles="USER,ADMINISTRATOR"/>
        <route id="administration" roles="ADMINISTRATOR"/>
    </routes>
</xml>
'
        );
        $this->xml2 = $xml2->security;
    }

    public function getResult()
    {
        $results = [];

        $request = new Request();
        $request->setMethod("GET");

        $configurations = ["users@xml"=>$this->xml1, "users@dao"=>$this->xml2];

        foreach ($configurations as $description=>$xml) {
            $request->setUri("asdf");
            $object = new XMLWrapper($xml, $request, null);
            $results[] = new Result($object->getResult()->getStatus()==ResultStatus::NOT_FOUND, "test path not found (".$description.")");

            $request->setUri("login");
            $object = new XMLWrapper($xml, $request, null);
            $results[] = new Result($object->getResult()->getStatus()==ResultStatus::OK, "guest allowed to login (".$description.")");

            $request->setUri("index");
            $object = new XMLWrapper($xml, $request, null);
            $results[] = new Result($object->getResult()->getStatus()==ResultStatus::UNAUTHORIZED, "guest unauthorized to index (".$description.")");

            $request->setUri("index");
            $object = new XMLWrapper($xml, $request, 1);
            $results[] = new Result($object->getResult()->getStatus()==ResultStatus::OK, "user allowed to index (".$description.")");

            $request->setUri("administration");
            $object = new XMLWrapper($xml, $request, 1);
            $results[] = new Result($object->getResult()->getStatus()==ResultStatus::FORBIDDEN, "user forbidden to administration (".$description.")");
        }

        return $results;
    }
}
