<?php

namespace OPNsense\Bind\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class ViewController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'view';
    protected static $internalModelClass = '\OPNsense\Bind\View';

    public function searchViewAction()
    {
        return $this->searchBase(
            'views.view',
            ['enabled', 'sequence', 'name', 'matchany', 'recursion', 'allowqueryany'],
            'sequence'
        );
    }

    public function getViewAction($uuid = null)
    {
        return $this->getBase('view', 'views.view', $uuid);
    }

    public function addViewAction()
    {
        return $this->addBase('view', 'views.view');
    }

    public function setViewAction($uuid = null)
    {
        return $this->setBase('view', 'views.view', $uuid);
    }

    public function delViewAction($uuid)
    {
        return $this->delBase('views.view', $uuid);
    }

    public function toggleViewAction($uuid)
    {
        return $this->toggleBase('views.view', $uuid);
    }
}
