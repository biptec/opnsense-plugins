<?php

namespace OPNsense\ApiExtensions\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Backend;

class CarpHealthController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\\OPNsense\\ApiExtensions\\CarpHealth';
    protected static $internalModelName = 'carp_health';

    public function searchCheckAction()
    {
        return $this->searchBase('checks.check', ['enabled', 'name', 'interface', 'target']);
    }

    public function getCheckAction($uuid = null)
    {
        return $this->getBase('check', 'checks.check', $uuid);
    }

    public function addCheckAction()
    {
        return $this->addBase('check', 'checks.check');
    }

    public function setCheckAction($uuid)
    {
        return $this->setBase('check', 'checks.check', $uuid);
    }

    public function delCheckAction($uuid)
    {
        return $this->delBase('checks.check', $uuid);
    }

    public function reconfigureAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $backend = new Backend();
        $result = trim($backend->configdRun('api_extensions carp_health_restart'));
        if ($result === 'ok') {
            $backend->configdRun('interface update carp service_status');
        }
        return ['status' => $result === 'ok' ? 'ok' : 'failed', 'result' => $result];
    }

    public function statusAction(): array
    {
        if (!$this->request->isGet()) {
            return ['status' => 'failed'];
        }
        $result = trim((new Backend())->configdRun('api_extensions carp_health_status'));
        $decoded = json_decode($result, true);
        return is_array($decoded) ? $decoded : ['status' => 'failed', 'result' => $result];
    }
}
