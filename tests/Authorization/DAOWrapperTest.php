<?php

namespace Test\Lucinda\WebSecurity\Authorization;

use Lucinda\UnitTest\Validator\Strings;
use Lucinda\WebSecurity\Authorization\DAOWrapper;
use Lucinda\WebSecurity\Authorization\ResultStatus;
use Lucinda\WebSecurity\Request;

class DAOWrapperTest
{
    private \SimpleXMLElement $xml;

    public function __construct()
    {
        $this->xml = \simplexml_load_string(
            '
<security>
    <authorization>
        <by_dao page_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockPageAuthorizationDAO" user_dao="Test\Lucinda\WebSecurity\mocks\Authorization\MockUserAuthorizationDAO"/>
    </authorization>
</security>
'
        );
    }

    public function getResult()
    {
        $results = [];

        $request = new Request();
        $request->setMethod("GET");

        $request->setUri("asdf");
        $object = new DAOWrapper($this->xml, $request, null);
        $results[] = (new Strings($object->getResult()->getStatus()->name))->assertEquals(ResultStatus::NOT_FOUND->name, "test path not found");

        $request->setUri("login");
        $object = new DAOWrapper($this->xml, $request, null);
        $results[] = (new Strings($object->getResult()->getStatus()->name))->assertEquals(ResultStatus::OK->name, "guest allowed to login");

        $request->setUri("index");
        $object = new DAOWrapper($this->xml, $request, null);
        $results[] = (new Strings($object->getResult()->getStatus()->name))->assertEquals(ResultStatus::UNAUTHORIZED->name, "guest unauthorized to index");

        $request->setUri("index");
        $object = new DAOWrapper($this->xml, $request, 1);
        $results[] = (new Strings($object->getResult()->getStatus()->name))->assertEquals(ResultStatus::OK->name, "user allowed to index");

        $request->setUri("administration");
        $object = new DAOWrapper($this->xml, $request, 1);
        $results[] = (new Strings($object->getResult()->getStatus()->name))->assertEquals(ResultStatus::FORBIDDEN->name, "user forbidden to administration");

        return $results;
    }
}
