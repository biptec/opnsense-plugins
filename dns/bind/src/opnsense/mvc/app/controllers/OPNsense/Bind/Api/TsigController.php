<?php

namespace OPNsense\Bind\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class TsigController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'key';
    protected static $internalModelClass = '\OPNsense\Bind\Tsig';

    public function searchKeyAction()
    {
        return $this->searchBase('keys.key', ['enabled', 'name', 'algorithm'], 'name');
    }

    public function getKeyAction($uuid = null)
    {
        return $this->getBase('key', 'keys.key', $uuid);
    }

    public function addKeyAction()
    {
        return $this->addBase('key', 'keys.key');
    }

    public function setKeyAction($uuid = null)
    {
        return $this->setBase('key', 'keys.key', $uuid);
    }

    public function delKeyAction($uuid)
    {
        return $this->delBase('keys.key', $uuid);
    }

    public function toggleKeyAction($uuid)
    {
        return $this->toggleBase('keys.key', $uuid);
    }

    public function generateSecretAction()
    {
        return ['secret' => base64_encode(random_bytes(32))];
    }
}
