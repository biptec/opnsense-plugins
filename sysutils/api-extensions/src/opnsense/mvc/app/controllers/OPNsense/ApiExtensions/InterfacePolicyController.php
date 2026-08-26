<?php

namespace OPNsense\ApiExtensions;

class InterfacePolicyController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/ApiExtensions/interface_policy');
        $this->view->policyForm = $this->getForm('interfaceSyncPolicy');
    }
}
