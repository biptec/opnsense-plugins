<?php

namespace OPNsense\ApiExtensions;

class CarpHealthController extends \OPNsense\Base\IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/ApiExtensions/carp_health');
        $this->view->settingsForm = $this->getForm('carpHealthSettings');
        $this->view->checkForm = $this->getForm('carpHealthCheck');
    }
}
